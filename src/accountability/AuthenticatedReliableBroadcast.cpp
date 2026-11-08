#include "AuthenticatedReliableBroadcast.hpp"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>
namespace pvia { namespace {
constexpr u64 RBC_DOMAIN=0x5056494152424331ULL;
constexpr u64 RBC_PREFLIGHT_KIND=0x5242435052463031ULL;
constexpr u64 RBC_INIT_KIND=0x524243494e493031ULL;
constexpr u64 RBC_ECHO_KIND=0x5242434543483031ULL;
constexpr u64 RBC_READY_KIND=0x5242435244593031ULL;
constexpr u64 RBC_SUMMARY_KIND=0x52424353554d3031ULL;
constexpr u64 RBC_FINAL_KIND=0x52424346494e3031ULL;
constexpr u64 RBC_WIRE_MAGIC=0x5056494152425749ULL;
constexpr u64 RBC_SUMMARY_MAGIC=0x5056494152425355ULL;
constexpr size_t RBC_HEADER_WORDS=8, RBC_MAX_PAYLOAD_WORDS=4096;
constexpr uint32_t RBC_NONE=0, RBC_INIT=1, RBC_ECHO=2, RBC_READY=3;
constexpr uint32_t RBC_N=4, RBC_T=1;
constexpr uint32_t RBC_ECHO_THRESHOLD=RBC_N-RBC_T;
constexpr uint32_t RBC_READY_RELAY_THRESHOLD=RBC_T+1;
constexpr uint32_t RBC_DELIVER_THRESHOLD=2*RBC_T+1;
constexpr uint64_t RBC_CONTEXT_SPAN=16;
void append_digest_words(const Digest& d,std::vector<u64>* w){
 if(!w)return;for(size_t i=0;i<4;++i){u64 x=0;std::memcpy(&x,d.bytes.data()+8*i,8);w->push_back(x);}
}
Digest digest_from_words(const u64* w){
 Digest d{};if(!w)return d;for(size_t i=0;i<4;++i)std::memcpy(d.bytes.data()+8*i,w+i,8);return d;
}
bool make_context(const AuthenticatedMpcMessageContext& b,uint64_t off,u64 kind,AuthenticatedMpcMessageContext* out){
 if(!out||off>RBC_CONTEXT_SPAN||b.round>std::numeric_limits<uint64_t>::max()-off||
 b.sequence>std::numeric_limits<uint64_t>::max()-off)return false;
 *out=b;out->round+=off;out->sequence+=off;out->message_kind=kind;return validate_authenticated_mpc_message_context(*out);
}
struct WirePacket{uint32_t type=RBC_NONE;Digest binding{};std::vector<u64> payload;};
std::vector<u64> encode_packet(uint32_t type,int broadcaster,size_t n,const std::vector<u64>& p){
 std::vector<u64> out={RBC_WIRE_MAGIC,type,static_cast<u64>(broadcaster),static_cast<u64>(n)};
 if(type==RBC_NONE){out.resize(RBC_HEADER_WORDS+n,0);out[0]=RBC_WIRE_MAGIC;out[1]=RBC_NONE;out[2]=static_cast<u64>(broadcaster);out[3]=static_cast<u64>(n);return out;}
 if(p.size()!=n)return{};Digest d=compute_authenticated_mpc_payload_binding(p);if(d==Digest{})return{};
 append_digest_words(d,&out);out.insert(out.end(),p.begin(),p.end());return out;
}
bool decode_packet(const u64* w,size_t nw,int broadcaster,size_t n,uint32_t expected,WirePacket* out){
 if(!w||!out||nw!=RBC_HEADER_WORDS+n||w[0]!=RBC_WIRE_MAGIC||w[2]!=static_cast<u64>(broadcaster)||w[3]!=static_cast<u64>(n)||w[1]>RBC_READY)return false;
 uint32_t type=static_cast<uint32_t>(w[1]);
 if(type==RBC_NONE){for(size_t i=4;i<nw;++i)if(w[i]!=0)return false;out->type=RBC_NONE;out->binding=Digest{};out->payload.clear();return true;}
 if(type!=expected)return false;Digest d=digest_from_words(w+4);std::vector<u64> p(w+RBC_HEADER_WORDS,w+nw);
 if(d==Digest{}||compute_authenticated_mpc_payload_binding(p)!=d)return false;
 out->type=type;out->binding=d;out->payload=std::move(p);return true;
}
struct ValueSupport{Digest binding{};std::vector<u64> payload;std::set<int> senders;};
using SupportMap=std::map<std::string,ValueSupport>;
void add_support(SupportMap* m,int sender,const WirePacket& p){
 if(!m||p.type==RBC_NONE||p.binding==Digest{})return;std::string k=p.binding.hex();auto it=m->find(k);
 if(it==m->end()){ValueSupport s;s.binding=p.binding;s.payload=p.payload;s.senders.insert(sender);m->emplace(k,std::move(s));}
 else if(it->second.payload==p.payload)it->second.senders.insert(sender);
}
bool run_impl(int rank,int world,int broadcaster,const std::vector<u64>& local,size_t n,
 const AuthenticatedMpcMessageContext& base,const AuthenticatedMpcExchange& exchange,
 AuthenticatedReliableBroadcastResult* result,const std::vector<std::vector<u64>>* test_init,
 int ready_equivocator,const std::vector<std::vector<u64>>* test_ready){
 AuthenticatedReliableBroadcastResult fallback;
 const bool result_supplied=result!=nullptr;
 if(!result)result=&fallback;
 *result=AuthenticatedReliableBroadcastResult{};
 AuthenticatedMpcMessageContext pre;
 int actual_rank=-1,actual_world=0;
 MPI_Comm_rank(MPI_COMM_WORLD,&actual_rank);MPI_Comm_size(MPI_COMM_WORLD,&actual_world);
 const bool pre_context_valid=make_context(base,0,RBC_PREFLIGHT_KIND,&pre);
 bool valid=result_supplied&&rank==actual_rank&&world==actual_world&&world==4&&
  rank>=0&&rank<world&&broadcaster>=0&&broadcaster<world&&n>0&&n<=RBC_MAX_PAYLOAD_WORDS&&
  exchange.ready()&&pre_context_valid&&base.protocol_domain!=0&&base.sid!=0&&base.checkpoint!=0&&
  base.round<=std::numeric_limits<uint64_t>::max()-RBC_CONTEXT_SPAN&&
  base.sequence<=std::numeric_limits<uint64_t>::max()-RBC_CONTEXT_SPAN;
 valid=valid&&(rank==broadcaster?local.size()==n:local.empty());
 if(test_init){valid=valid&&rank==broadcaster&&test_init->size()==static_cast<size_t>(world);if(valid)for(const auto& v:*test_init)if(v.size()!=n)valid=false;}
 if(test_ready){valid=valid&&ready_equivocator>=0&&ready_equivocator<world&&test_ready->size()==static_cast<size_t>(world);if(valid)for(const auto& v:*test_ready)if(v.size()!=n)valid=false;}
 int local_preflight=valid?1:0,all_preflight=0;
 MPI_Allreduce(&local_preflight,&all_preflight,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
 if(!all_preflight)return false;
 bool pre_ok=false;Digest pre_binding{};
 if(!exchange.AllTrue(pre,valid,&pre_ok,&pre_binding)||!pre_ok||pre_binding==Digest{})return false;
 const size_t pw=RBC_HEADER_WORDS+n;std::vector<Digest> phase_bindings;
 auto xround=[&](uint64_t off,u64 kind,uint32_t st,const std::vector<u64>& sv,uint32_t expected,std::vector<u64>* recv,Digest* binding)->bool{
  AuthenticatedMpcMessageContext ctx;if(!make_context(base,off,kind,&ctx))return false;
  std::vector<u64> outgoing(static_cast<size_t>(world)*pw,0);
  for(int receiver=0;receiver<world;++receiver){uint32_t wire_type=st;const std::vector<u64>* v=&sv;
   if(kind==RBC_INIT_KIND&&test_init&&rank==broadcaster){wire_type=RBC_INIT;v=&(*test_init)[static_cast<size_t>(receiver)];}
   if(kind==RBC_READY_KIND&&test_ready&&rank==ready_equivocator){wire_type=RBC_READY;v=&(*test_ready)[static_cast<size_t>(receiver)];}
   if(wire_type!=RBC_NONE&&(!v||v->size()!=n))return false;const std::vector<u64> empty;
   auto packet=encode_packet(wire_type,broadcaster,n,wire_type==RBC_NONE?empty:*v);if(packet.size()!=pw)return false;
   std::copy(packet.begin(),packet.end(),outgoing.begin()+static_cast<std::ptrdiff_t>(static_cast<size_t>(receiver)*pw));}
  if(!exchange.AllToAllWords(ctx,outgoing,pw,recv,binding)||!recv||recv->size()!=static_cast<size_t>(world)*pw||*binding==Digest{})return false;
  phase_bindings.push_back(*binding);(void)expected;return true;
 };
 std::vector<u64> received;Digest phase{};uint32_t init_type=rank==broadcaster?RBC_INIT:RBC_NONE;
 std::vector<u64> init_value=rank==broadcaster?local:std::vector<u64>{};
 if(!xround(1,RBC_INIT_KIND,init_type,init_value,RBC_INIT,&received,&phase))return false;
 bool have=false;std::vector<u64> my_value;
 {size_t off=static_cast<size_t>(broadcaster)*pw;WirePacket p;if(decode_packet(received.data()+off,pw,broadcaster,n,RBC_INIT,&p)&&p.type==RBC_INIT){have=true;my_value=p.payload;}}
 uint32_t echo_type=have?RBC_ECHO:RBC_NONE;std::vector<u64> echo_value=have?my_value:std::vector<u64>{};
 if(!xround(2,RBC_ECHO_KIND,echo_type,echo_value,RBC_ECHO,&received,&phase))return false;
 SupportMap echoes;for(int s=0;s<world;++s){WirePacket p;size_t off=static_cast<size_t>(s)*pw;if(decode_packet(received.data()+off,pw,broadcaster,n,RBC_ECHO,&p)&&p.type==RBC_ECHO)add_support(&echoes,s,p);}
 SupportMap readies;bool ready_sent=false,delivered=false,consistent=true;Digest delivered_binding{};std::vector<u64> delivered_payload;uint32_t max_echo=0;
 for(const auto& x:echoes)max_echo=std::max(max_echo,static_cast<uint32_t>(x.second.senders.size()));
 for(uint64_t rr=0;rr<5;++rr){uint32_t st=RBC_NONE;std::vector<u64> sv;
  if(!ready_sent){std::map<std::string,ValueSupport> eligible;
   for(const auto& x:echoes)if(x.second.senders.size()>=RBC_ECHO_THRESHOLD)eligible.emplace(x.first,x.second);
   for(const auto& x:readies)if(x.second.senders.size()>=RBC_READY_RELAY_THRESHOLD)eligible.emplace(x.first,x.second);
   if(eligible.size()>1)consistent=false;else if(eligible.size()==1){st=RBC_READY;sv=eligible.begin()->second.payload;ready_sent=true;}}
  if(!xround(3+rr,RBC_READY_KIND,st,sv,RBC_READY,&received,&phase))return false;
  for(int s=0;s<world;++s){WirePacket p;size_t off=static_cast<size_t>(s)*pw;if(decode_packet(received.data()+off,pw,broadcaster,n,RBC_READY,&p)&&p.type==RBC_READY)add_support(&readies,s,p);}
  std::vector<std::string> candidates;for(const auto& x:readies)if(x.second.senders.size()>=RBC_DELIVER_THRESHOLD)candidates.push_back(x.first);
  if(candidates.size()>1)consistent=false;else if(candidates.size()==1){const auto& x=readies.at(candidates.front());if(delivered&&delivered_binding!=x.binding)consistent=false;delivered=true;delivered_binding=x.binding;delivered_payload=x.payload;}
 }
 uint32_t echo_count=0,ready_count=0;
 if(delivered){auto e=echoes.find(delivered_binding.hex());if(e!=echoes.end())echo_count=static_cast<uint32_t>(e->second.senders.size());auto r=readies.find(delivered_binding.hex());if(r!=readies.end())ready_count=static_cast<uint32_t>(r->second.senders.size());}
 else for(const auto& x:readies)ready_count=std::max(ready_count,static_cast<uint32_t>(x.second.senders.size()));
 AuthenticatedMpcMessageContext sc;if(!make_context(base,8,RBC_SUMMARY_KIND,&sc))return false;
 std::vector<u64> summary={RBC_SUMMARY_MAGIC,delivered?1ULL:0ULL};append_digest_words(delivered?delivered_binding:Digest{},&summary);summary.push_back(consistent?1ULL:0ULL);
 std::vector<u64> summaries;Digest summary_transport{};
 if(!exchange.AllGatherWords(sc,summary,&summaries,&summary_transport)||summaries.size()!=static_cast<size_t>(world)*summary.size()||summary_transport==Digest{})return false;
 struct Outcome{bool delivered;Digest binding;uint32_t support;};std::map<std::string,Outcome> outcomes;bool summaries_valid=true;
 for(int s=0;s<world;++s){size_t off=static_cast<size_t>(s)*summary.size();
  if(summaries[off]!=RBC_SUMMARY_MAGIC||summaries[off+1]>1||summaries[off+6]>1){summaries_valid=false;continue;}
  bool pd=summaries[off+1]!=0;Digest d=digest_from_words(&summaries[off+2]);if((pd&&d==Digest{})||(!pd&&d!=Digest{})){summaries_valid=false;continue;}
  std::string key=std::string(pd?"1:":"0:")+d.hex();auto it=outcomes.find(key);if(it==outcomes.end())outcomes.emplace(key,Outcome{pd,d,1});else ++it->second.support;}
 Outcome winner{false,Digest{},0};bool has_winner=false;
 for(const auto& x:outcomes)if(x.second.support>=RBC_ECHO_THRESHOLD){if(has_winner)summaries_valid=false;winner=x.second;has_winner=true;}
 bool matches=has_winner&&delivered==winner.delivered&&(delivered?delivered_binding==winner.binding:delivered_binding==Digest{});
 bool local_consistent=summaries_valid&&consistent&&matches;
 AuthenticatedMpcMessageContext fc;if(!make_context(base,9,RBC_FINAL_KIND,&fc))return false;bool all_consistent=false;Digest final_binding{};
 if(!exchange.AllTrue(fc,local_consistent,&all_consistent,&final_binding)||!all_consistent||final_binding==Digest{})return false;
 std::vector<u64> transcript={RBC_DOMAIN,static_cast<u64>(broadcaster),static_cast<u64>(n),winner.delivered?1ULL:0ULL,static_cast<u64>(winner.support)};
 append_digest_words(compute_authenticated_mpc_context_binding(base),&transcript);append_digest_words(pre_binding,&transcript);for(const auto& d:phase_bindings)append_digest_words(d,&transcript);
 append_digest_words(summary_transport,&transcript);append_digest_words(final_binding,&transcript);append_digest_words(winner.binding,&transcript);
 Digest final_transcript=hash_words(transcript);if(final_transcript==Digest{})return false;
 result->available=true;result->delivered=winner.delivered;if(winner.delivered){result->payload=delivered_payload;result->value_binding=winner.binding;}
 result->transcript_binding=final_transcript;result->echo_support=echo_count?echo_count:max_echo;result->ready_support=ready_count;
 result->authenticated_point_to_point=true;result->synchronous_round_model=true;result->process_crash_tolerant=false;return true;
}
} // namespace
bool authenticated_reliable_broadcast_n4(int rank,int world,int broadcaster,const std::vector<u64>& local,size_t n,
 const AuthenticatedMpcMessageContext& base,const AuthenticatedMpcExchange& exchange,AuthenticatedReliableBroadcastResult* result){
 return run_impl(rank,world,broadcaster,local,n,base,exchange,result,nullptr,-1,nullptr);
}
bool run_authenticated_reliable_broadcast_n4_selftest(int rank,int world,const AuthenticatedMpcExchange& exchange){
 if(world!=4||rank<0||rank>=4)return false;const std::vector<u64> value={0x5056494152424354ULL,77ULL,1234ULL,1ULL};
 AuthenticatedMpcMessageContext ctx;ctx.protocol_domain=RBC_DOMAIN;ctx.sid=0x52424353454c4631ULL;ctx.checkpoint=0x5242434e340001ULL;ctx.round=10;ctx.sequence=10;ctx.message_kind=RBC_INIT_KIND;
 AuthenticatedReliableBroadcastResult honest;const std::vector<u64> local=rank==0?value:std::vector<u64>{};
 bool call=authenticated_reliable_broadcast_n4(rank,world,0,local,value.size(),ctx,exchange,&honest);
 bool honest_ok=call&&honest.available&&honest.delivered&&honest.payload==value&&honest.value_binding==compute_authenticated_mpc_payload_binding(value)&&honest.transcript_binding!=Digest{}&&honest.echo_support>=3&&honest.ready_support>=3&&!honest.process_crash_tolerant;
 AuthenticatedMpcMessageContext badctx=ctx;badctx.round=40;badctx.sequence=40;std::vector<std::vector<u64>> per_receiver;
 for(int r=0;r<4;++r)per_receiver.push_back({0x5056494152455156ULL,static_cast<u64>(r),static_cast<u64>(r+100),9ULL});
 AuthenticatedReliableBroadcastResult bad;const std::vector<u64> empty;const auto* injected=rank==0?&per_receiver:nullptr;
 bool bad_call=run_impl(rank,world,0,rank==0?value:empty,value.size(),badctx,exchange,&bad,injected,-1,nullptr);
 bool bad_ok=bad_call&&bad.available&&!bad.delivered&&bad.payload.empty()&&bad.value_binding==Digest{}&&bad.transcript_binding!=Digest{};
 AuthenticatedMpcMessageContext readyctx=ctx;readyctx.round=80;readyctx.sequence=80;
 std::vector<u64> conflicting_value=value;conflicting_value[2]^=0xBAD5EEDULL;
 std::vector<std::vector<u64>> per_receiver_ready;
 for(int r=0;r<world;++r)per_receiver_ready.push_back(r==2?conflicting_value:value);
 AuthenticatedReliableBroadcastResult ready_conflict;
 bool ready_call=run_impl(rank,world,0,rank==0?value:empty,value.size(),readyctx,exchange,&ready_conflict,nullptr,1,&per_receiver_ready);
 bool ready_ok=ready_call&&ready_conflict.available&&ready_conflict.delivered&&ready_conflict.payload==value&&ready_conflict.value_binding==compute_authenticated_mpc_payload_binding(value)&&ready_conflict.transcript_binding!=Digest{}&&ready_conflict.echo_support>=3&&ready_conflict.ready_support>=3&&!ready_conflict.process_crash_tolerant;
 AuthenticatedMpcMessageContext invalidctx=ctx;invalidctx.round=120;invalidctx.sequence=120;
 if(rank==2)invalidctx.protocol_domain=0;
 AuthenticatedReliableBroadcastResult invalidctx_result;
 bool invalidctx_call=authenticated_reliable_broadcast_n4(rank,world,0,rank==0?value:empty,value.size(),invalidctx,exchange,&invalidctx_result);
 bool invalidctx_ok=!invalidctx_call&&!invalidctx_result.available;
 AuthenticatedMpcMessageContext nullctx=ctx;nullctx.round=140;nullctx.sequence=140;
 AuthenticatedReliableBroadcastResult null_result;
 bool null_result_call=authenticated_reliable_broadcast_n4(rank,world,0,rank==0?value:empty,value.size(),nullctx,exchange,rank==3?nullptr:&null_result);
 bool null_result_ok=!null_result_call&&(rank==3||!null_result.available);
 int local_ok=honest_ok&&bad_ok&&ready_ok&&invalidctx_ok&&null_result_ok?1:0,all_ok=0;MPI_Allreduce(&local_ok,&all_ok,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
 if(rank==0)std::cout<<"[PVIA][authenticated-rbc-n4] "<<(all_ok?"PASS":"FAIL")<<" honest_delivery="<<(honest_ok?"PASS":"FAIL")<<" sender_equivocation="<<(bad_ok?"NO_DELIVERY":"FAIL")<<" ready_equivocation="<<(ready_ok?"CONSISTENT_DELIVERY":"FAIL")
  <<" invalid_context="<<(invalidctx_ok?"REJECTED":"FAIL")
  <<" null_result="<<(null_result_ok?"REJECTED":"FAIL")
  <<" n=4 t=1 model=synchronous_rounds process_crash_tolerance=false"<<std::endl;
 return all_ok!=0;
}
} // namespace pvia
