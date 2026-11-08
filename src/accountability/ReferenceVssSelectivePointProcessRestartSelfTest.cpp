#include "ReferenceVssSelectivePointSelfTest.hpp"
#include "ReferenceBivariateVss.hpp"
#include "ReferenceVssSelectivePointCommitment.hpp"
#include "ReferenceVssSelectivePointRegistryStore.hpp"
#include "ReferenceVssSelectivePointDurableReplay.hpp"
#include "ReferenceVssSelectiveReleaseCoordinator.hpp"
#include "TransferAuthentication.hpp"
#include <mpi.h>
#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
namespace pvia {
namespace {
constexpr u64 PM=0x5056435052504931ULL, SM=0x5056435052534831ULL;
constexpr u64 DM=0x5056435052444c31ULL, CM=0x5056434352415348ULL, SID=0x50564350524f4353ULL;
constexpr CheckpointId CP=0x4350524f430001ULL;
constexpr size_t E=12;
void add_digest(const Digest& d,std::vector<u64>* w) {
 for(size_t i=0;i<4;++i){u64 x=0;for(size_t j=0;j<8;++j)x|=u64(d.bytes[i*8+j])<<(8*j);w->push_back(x);}
}
Digest get_digest(const std::vector<u64>& w,size_t at) {
 Digest d{};if(at>w.size()||w.size()-at<4)return d;
 for(size_t i=0;i<4;++i)for(size_t j=0;j<8;++j)d.bytes[i*8+j]=uint8_t(w[at+i]>>(8*j));return d;
}
bool write_words(const std::string& dir,const std::string& path,const std::vector<u64>& w) {
 if(w.empty()||w.size()>(1U<<20))return false;
 std::vector<uint8_t>b(w.size()*8);
 for(size_t i=0;i<w.size();++i)for(size_t j=0;j<8;++j)b[i*8+j]=uint8_t(w[i]>>(8*j));
 int fd=::open(path.c_str(),O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC|O_NOFOLLOW,0600);
 if(fd<0)return false;size_t p=0;bool ok=true;
 while(p<b.size()){ssize_t n=::write(fd,b.data()+p,b.size()-p);if(n<0&&errno==EINTR)continue;if(n<=0){ok=false;break;}p+=size_t(n);}
 if(ok)ok=::fsync(fd)==0;if(::close(fd)!=0)ok=false;
 if(ok){int d=::open(dir.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);if(d<0)ok=false;else{if(::fsync(d)!=0)ok=false;if(::close(d)!=0)ok=false;}}
 if(!ok)::unlink(path.c_str());return ok;
}
bool read_words(const std::string& path,std::vector<u64>* w) {
 if(!w)return false;w->clear();int fd=::open(path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return false;
 struct stat s{};bool ok=::fstat(fd,&s)==0&&S_ISREG(s.st_mode)&&s.st_uid==::geteuid()&&(s.st_mode&077)==0&&s.st_nlink==1&&s.st_size>0&&s.st_size%8==0&&s.st_size<=off_t((1U<<20)*8);
 std::vector<uint8_t>b;if(ok)b.resize(size_t(s.st_size));size_t p=0;
 while(ok&&p<b.size()){ssize_t n=::read(fd,b.data()+p,b.size()-p);if(n<0&&errno==EINTR)continue;if(n<=0){ok=false;break;}p+=size_t(n);}
 if(::close(fd)!=0)ok=false;if(!ok)return false;w->assign(b.size()/8,0);
 for(size_t i=0;i<w->size();++i)for(size_t j=0;j<8;++j)(*w)[i]|=u64(b[i*8+j])<<(8*j);return true;
}
bool receipt_from(const ReferenceVssLocalWitness& l,ReferenceVssReceipt* r) {
 if(!r||!validate_reference_vss_local_witness(l))return false;
 r->available=r->consistent=true;r->dealer=l.dealer;r->world_size=l.transcript_context.world_size;r->threshold=l.threshold;r->element_count=l.element_count;r->local_row_commitment=l.local_row_commitment;r->transcript_binding=l.transcript_binding;r->transcript_context=l.transcript_context;return true;
}
bool pins_from(const std::string& p,Digest* r,Digest* n,Digest* g,Digest* a) {
 std::vector<u64>w;if(!r||!n||!g||!a||!read_words(p,&w)||w.size()!=18||w[0]!=PM||w[1]!=1)return false;
 *r=get_digest(w,2);*n=get_digest(w,6);*g=get_digest(w,10);*a=get_digest(w,14);
 return *r!=Digest{}&&*n!=Digest{}&&*g!=Digest{}&&*a!=Digest{};
}
bool exists(const std::string& p){struct stat s{};return ::lstat(p.c_str(),&s)==0;}
}
bool run_reference_vss_selective_point_process_restart_selftest(
 int rank,int n,const std::string& phase,const std::string& dir) {
 if(n!=4||rank<0||rank>=n||dir.empty()||dir.size()>3000||
    (phase!="prepare"&&phase!="crash_prepare"&&phase!="crash_journal_prepare"&&phase!="resume"&&phase!="journal_resume"&&phase!="duplicate"))return false;
 struct stat ds{};if(::stat(dir.c_str(),&ds)!=0||!S_ISDIR(ds.st_mode)||ds.st_uid!=::geteuid()||(ds.st_mode&077)!=0)return false;
 auto& auth=Ed25519TransferAuthenticator::instance();if(!auth.Initialize(rank,n))return false;
 AuthenticatedMpcExchange exchange(rank,n);if(!exchange.ready())return false;
 const std::string rp=dir+"/registry.record",jp=dir+"/replay.journal",ap=dir+"/replay.anchor";
 const std::string pp=dir+"/pins.words",sp=dir+"/expected.share",mp=dir+"/delivered.marker";
 const std::string lp=dir+"/local.rank"+std::to_string(rank)+".words";
 AuthenticatedMpcMessageContext setup;setup.protocol_domain=PVIA_VSS_SELECTIVE_POINT_DOMAIN;setup.sid=SID;setup.checkpoint=CP;setup.round=1;setup.sequence=1;setup.message_kind=PVIA_VSS_POINT_SETUP_KIND;
 AuthenticatedMpcMessageContext ctx;ctx.protocol_domain=PVIA_VSS_SELECTIVE_POINT_DOMAIN;ctx.sid=SID;ctx.checkpoint=CP;ctx.round=41;ctx.sequence=73;ctx.message_kind=PVIA_VSS_SELECTIVE_POINT_KIND;
 const std::vector<int> helpers{1,2,3};
 ReferenceVssLocalWitness local;ReferenceVssReceipt receipt;
 if(phase=="prepare"||phase=="crash_prepare"||phase=="crash_journal_prepare") {
  ReferenceBivariateVss vss(rank,n,1);if(!vss.valid())return false;
  std::vector<F> plain,share;if(rank==0)for(size_t i=0;i<E;++i)plain.emplace_back(static_cast<long long>(i+31),static_cast<long long>(2*i+41));
  if(!vss.ShareVectorFromDealerWithLocalWitness(0,plain,&share,&receipt,&local)||!receipt.available||!receipt.consistent||!validate_reference_vss_local_witness(local)||share.size()!=E)return false;
  ReferenceVssSelectivePointCommitmentRegistry registry;
  if(!establish_reference_vss_point_commitment_registry(local,receipt,exchange,setup,&registry))return false;
  int saved=write_words(dir,lp,encode_reference_vss_local_witness(local))?1:0;
  Digest record{},native{},initial{};
  if(rank==0) {
   std::vector<u64> native_words{0x5056434e41544956ULL,SID,CP};add_digest(registry.registry_binding,&native_words);add_digest(auth.RegistryCommitment(),&native_words);native=hash_words(native_words);
   saved=saved&&native!=Digest{}&&save_reference_vss_point_registry_execution_record(rp,registry,native,&record);
   ReferenceVssSelectivePointDurableReplayGuard j(jp,registry.registry_binding);
   ReferenceVssSelectivePointReplayHeadAnchor a(ap,registry.registry_binding);
   saved=saved&&j.InitializeNew()&&j.ReadCurrentHead(&initial)&&initial!=Digest{}&&a.InitializeNew(initial);
   std::vector<u64> pins{PM,1};add_digest(record,&pins);add_digest(native,&pins);add_digest(registry.registry_binding,&pins);add_digest(auth.RegistryCommitment(),&pins);
   saved=saved&&write_words(dir,pp,pins);
   std::vector<u64> sh{SM,E};for(const F& x:share){sh.push_back(x.real);sh.push_back(x.img);}saved=saved&&write_words(dir,sp,sh);
  }
  int all=0;MPI_Allreduce(&saved,&all,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);if(!all)return false;
  Digest rec{},nat{},reg{},authreg{};if(rank==0&&!pins_from(pp,&rec,&nat,&reg,&authreg))return false;
  ReferenceVssSelectiveReleasePins pins;ReferenceVssSelectivePointReplayHeadAnchor anchor(ap,rank==0?reg:Digest{});bool cas=false;
  if(rank==0) {
   pins.registry_path=rp;pins.replay_journal_path=jp;pins.independently_pinned_record=rec;pins.independently_pinned_native_execution=nat;pins.independently_pinned_registry_binding=reg;pins.independently_pinned_replay_head=initial;
   pins.load_current_head=[&anchor](Digest*h){return anchor.ReadCurrentHead(h);};
   pins.verify_independent_pins=[&anchor,rec,nat,reg](const Digest&r,const Digest&nn,const Digest&g,const Digest&h){Digest live{};return r==rec&&nn==nat&&g==reg&&anchor.ReadCurrentHead(&live)&&live==h;};
   pins.persist_new_head=[&anchor,&cas,&phase,&dir,jp,reg](const Digest&o,const Digest&v){
    if(phase=="crash_journal_prepare") {
     ReferenceVssSelectivePointDurableReplayGuard journal(jp,reg);
     Digest journal_head{},anchor_head{};
     if(!journal.ReadCurrentHead(&journal_head)||journal_head!=v||
        !anchor.ReadCurrentHead(&anchor_head)||anchor_head!=o)::_exit(85);
     std::vector<u64> crash_record{CM,2,static_cast<u64>(::getpid()),static_cast<u64>(SIGKILL)};
     add_digest(o,&crash_record);add_digest(v,&crash_record);
     const std::string crash_path=dir+"/crash.before_anchor_cas";
     if(!write_words(dir,crash_path,crash_record))::_exit(86);
     const char event[]="PVIA_FORCED_PROCESS_CRASH: SIGKILL_AFTER_JOURNAL_FSYNC_BEFORE_ANCHOR_CAS\n";
     (void)::write(STDERR_FILENO,event,sizeof(event)-1);
     (void)::kill(::getpid(),SIGKILL);
     ::_exit(86);
    }
    cas=anchor.CompareAndSwap(o,v);
    if(cas&&phase=="crash_prepare") {
     std::vector<u64> crash_record{CM,1,static_cast<u64>(::getpid()),static_cast<u64>(SIGKILL)};
     add_digest(o,&crash_record);add_digest(v,&crash_record);
     const std::string crash_path=dir+"/crash.after_anchor_cas";
     if(!write_words(dir,crash_path,crash_record))::_exit(86);
     const char event[]="PVIA_FORCED_PROCESS_CRASH: SIGKILL_AFTER_ANCHOR_CAS_BEFORE_RELEASE_RETURN\n";
     (void)::write(STDERR_FILENO,event,sizeof(event)-1);
     (void)::kill(::getpid(),SIGKILL);
     ::_exit(86);
    }
    return false;
   };
  }
  std::vector<F> out;Digest next{};ReferenceVssRecoveryProofWitness proof;
  bool accepted=release_reference_vss_selective_share_collective(exchange,local,0,receipt,local.transcript_context,ctx,rank==0?&pins:nullptr,&out,&next,&proof);
  int ok=1;
  if(rank==0){
   Digest ah{},jh{};ReferenceVssSelectivePointDurableReplayGuard j(jp,reg);
   if(phase=="crash_journal_prepare") {
    Digest pending{};
    ok=!accepted&&out.empty()&&next==Digest{}&&!proof.available&&!cas&&
       anchor.ReadCurrentHead(&ah)&&j.ReadCurrentHead(&jh)&&ah==initial&&
       jh!=initial&&j.VerifyPendingBatchWithPinnedHead(ctx,helpers,0,ah,&pending)&&pending==jh;
   } else {
    ok=!accepted&&out.empty()&&next==Digest{}&&!proof.available&&cas&&
       anchor.ReadCurrentHead(&ah)&&j.ReadCurrentHead(&jh)&&ah==jh&&ah!=initial&&
       j.VerifyCommittedBatchWithPinnedHead(ctx,helpers,0,ah);
   }
  }
  else ok=accepted&&out.empty()&&next==Digest{}&&!proof.available;
  int allok=0;MPI_Allreduce(&ok,&allok,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
  if(rank==0)std::cout<<"PVIA_VSS_SELECTIVE_PROCESS_RESTART: "<<(allok?"PASS":"FAIL")<<" phase=PREPARE local_witnesses=FSYNCED stable_identity=PASS journal_anchor="<<(phase=="crash_journal_prepare"?"PENDING":"COMMITTED")<<" output=WITHHELD"<<std::endl;
  return allok==1;
 }
 std::vector<u64> lw;if(!read_words(lp,&lw)||!decode_reference_vss_local_witness(lw,&local)||!validate_reference_vss_local_witness(local)||local.participant!=rank||local.dealer!=0||local.element_count!=E||!receipt_from(local,&receipt))return false;
 Digest rec{},nat{},reg{},authreg{},head{},pending_head{};int loaded=1;
 ReferenceVssSelectivePointReplayHeadAnchor anchor(ap,Digest{});ReferenceVssSelectivePointDurableReplayGuard journal(jp,Digest{});std::vector<F> expected;
 if(rank==0) {
  loaded=pins_from(pp,&rec,&nat,&reg,&authreg)&&auth.RegistryCommitment()==authreg;
  if(loaded){ReferenceVssPointRegistryExecutionRecord r;loaded=load_reference_vss_point_registry_execution_record(rp,rec,nat,SID,CP,receipt.transcript_binding,&r)&&r.registry.registry_binding==reg;}
  if(loaded){
   anchor=ReferenceVssSelectivePointReplayHeadAnchor(ap,reg);journal=ReferenceVssSelectivePointDurableReplayGuard(jp,reg);
   Digest jh{};loaded=anchor.ReadCurrentHead(&head)&&journal.ReadCurrentHead(&jh);
   if(loaded&&phase=="journal_resume")
    loaded=jh!=head&&journal.VerifyPendingBatchWithPinnedHead(ctx,helpers,0,head,&pending_head)&&pending_head==jh;
   else if(loaded)loaded=jh==head;
  }
  std::vector<u64> sh;loaded=loaded&&read_words(sp,&sh)&&sh.size()==2+2*E&&sh[0]==SM&&sh[1]==E;
  if(loaded)for(size_t i=0;i<E;++i)expected.emplace_back(static_cast<long long>(sh[2+2*i]),static_cast<long long>(sh[3+2*i]));
 }
 int all_loaded=0;MPI_Allreduce(&loaded,&all_loaded,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);if(!all_loaded)return false;
 ReferenceVssSelectiveReleasePins pins;int persist_calls=0;
 std::vector<int> authorized_helpers=helpers;
 if(rank==0) {
  pins.registry_path=rp;pins.replay_journal_path=jp;pins.independently_pinned_record=rec;pins.independently_pinned_native_execution=nat;pins.independently_pinned_registry_binding=reg;pins.independently_pinned_replay_head=head;
  pins.load_current_head=[&anchor](Digest*h){return anchor.ReadCurrentHead(h);};
  pins.verify_independent_pins=[&anchor,rec,nat,reg](const Digest&r,const Digest&nn,const Digest&g,const Digest&h){Digest live{};return r==rec&&nn==nat&&g==reg&&anchor.ReadCurrentHead(&live)&&live==h;};
  if(phase=="journal_resume") {
   pins.authorize_pending_resume=[&anchor,&journal,&authorized_helpers,ctx,head,pending_head,mp](const AuthenticatedMpcMessageContext& c,int t,const std::vector<int>& hs,const Digest& old_head,const Digest& new_head){
    Digest live{},observed_pending{};
    return !exists(mp)&&c.protocol_domain==ctx.protocol_domain&&c.sid==ctx.sid&&
      c.checkpoint==ctx.checkpoint&&c.round==ctx.round&&c.sequence==ctx.sequence&&
      c.message_kind==ctx.message_kind&&t==0&&hs==authorized_helpers&&
      old_head==head&&new_head==pending_head&&
      anchor.ReadCurrentHead(&live)&&live==old_head&&
      journal.VerifyPendingBatchWithPinnedHead(c,hs,t,old_head,&observed_pending)&&
      observed_pending==new_head;
   };
   pins.persist_new_head=[&anchor,&persist_calls](const Digest& old_head,const Digest& new_head){
    ++persist_calls;return anchor.CompareAndSwap(old_head,new_head);
   };
  } else {
   pins.authorize_committed_resume=[&anchor,ctx,&authorized_helpers,head,mp](const AuthenticatedMpcMessageContext& c,int t,const std::vector<int>& hs,const Digest& h){Digest live{};return !exists(mp)&&c.protocol_domain==ctx.protocol_domain&&c.sid==ctx.sid&&c.checkpoint==ctx.checkpoint&&c.round==ctx.round&&c.sequence==ctx.sequence&&c.message_kind==ctx.message_kind&&t==0&&hs==authorized_helpers&&h==head&&anchor.ReadCurrentHead(&live)&&live==h;};
   pins.persist_new_head=[&persist_calls](const Digest&,const Digest&){++persist_calls;return false;};
  }
 }
 if(phase=="resume"||phase=="journal_resume") {
  auto wrong_ctx=ctx;++wrong_ctx.round;++wrong_ctx.sequence;
  std::vector<F> wrong_out;Digest wrong_head{};ReferenceVssRecoveryProofWitness wrong_proof;
  bool wrong_accept=release_reference_vss_selective_share_collective(exchange,local,0,receipt,local.transcript_context,wrong_ctx,rank==0?&pins:nullptr,&wrong_out,&wrong_head,&wrong_proof);
  int wrong_ok=!wrong_accept&&wrong_out.empty()&&wrong_head==Digest{}&&!wrong_proof.available;
  if(rank==0){Digest ah{},jh{};const Digest expected_journal=(phase=="journal_resume"?pending_head:head);wrong_ok=wrong_ok&&anchor.ReadCurrentHead(&ah)&&journal.ReadCurrentHead(&jh)&&ah==head&&jh==expected_journal&&persist_calls==0;}
  int wrong_all=0;MPI_Allreduce(&wrong_ok,&wrong_all,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);if(!wrong_all)return false;

  authorized_helpers={1,2};
  std::vector<F> wrong_set_out;Digest wrong_set_head{};ReferenceVssRecoveryProofWitness wrong_set_proof;
  bool wrong_set_accept=release_reference_vss_selective_share_collective(exchange,local,0,receipt,local.transcript_context,ctx,rank==0?&pins:nullptr,&wrong_set_out,&wrong_set_head,&wrong_set_proof);
  int wrong_set_ok=!wrong_set_accept&&wrong_set_out.empty()&&wrong_set_head==Digest{}&&!wrong_set_proof.available;
  if(rank==0){Digest ah{},jh{};const Digest expected_journal=(phase=="journal_resume"?pending_head:head);wrong_set_ok=wrong_set_ok&&anchor.ReadCurrentHead(&ah)&&journal.ReadCurrentHead(&jh)&&ah==head&&jh==expected_journal&&persist_calls==0;}
  int wrong_set_all=0;MPI_Allreduce(&wrong_set_ok,&wrong_set_all,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);if(!wrong_set_all)return false;
  authorized_helpers=helpers;
 }
 std::vector<F> out;Digest outhead{};ReferenceVssRecoveryProofWitness proof;
 bool accepted=release_reference_vss_selective_share_collective(exchange,local,0,receipt,local.transcript_context,ctx,rank==0?&pins:nullptr,&out,&outhead,&proof);
 int ok=1;
 if(phase=="resume"||phase=="journal_resume") {
  const Digest delivered_head=(phase=="journal_resume"?pending_head:head);
  if(rank==0){
   Digest ah{},jh{};
   ok=accepted&&out==expected&&outhead==delivered_head&&proof.available&&
      proof.target==0&&proof.world_size==n&&proof.element_count==E&&
      proof.openings.size()==helpers.size()&&proof.commitments.size()==size_t(n*n)&&
      persist_calls==(phase=="journal_resume"?1:0)&&
      anchor.ReadCurrentHead(&ah)&&journal.ReadCurrentHead(&jh)&&
      ah==delivered_head&&jh==delivered_head&&
      journal.VerifyCommittedBatchWithPinnedHead(ctx,helpers,0,delivered_head);
   std::vector<u64> m{DM,1};add_digest(delivered_head,&m);ok=ok&&write_words(dir,mp,m);
  }
  else ok=accepted&&out.empty()&&outhead==Digest{}&&!proof.available;
  int allok=0;MPI_Allreduce(&ok,&allok,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
  if(rank==0)std::cout<<"PVIA_VSS_SELECTIVE_PROCESS_RESTART: "<<(allok?"PASS":"FAIL")<<" phase="<<(phase=="journal_resume"?"JOURNAL_RESUME":"RESUME")<<" fresh_mpi_process=PASS local_witness_reload=PASS stable_identity=PASS authenticated_openings=PASS exact_target_share=PASS journal_suffix="<<(phase=="journal_resume"?"REUSED":"COMMITTED")<<" anchor_cas="<<(phase=="journal_resume"?"RETRIED":"ALREADY_COMMITTED")<<" wrong_context_preflight=REJECTED wrong_helper_set_preflight=REJECTED delivery_marker=FSYNCED"<<std::endl;
  return allok==1;
 }
 std::vector<u64> marker;Digest ah{},jh{};
 if(rank==0)ok=!accepted&&out.empty()&&outhead==Digest{}&&!proof.available&&persist_calls==0&&exists(mp)&&read_words(mp,&marker)&&marker.size()==6&&marker[0]==DM&&anchor.ReadCurrentHead(&ah)&&journal.ReadCurrentHead(&jh)&&ah==head&&jh==head;
 else ok=!accepted&&out.empty()&&outhead==Digest{}&&!proof.available;
 int allok=0;MPI_Allreduce(&ok,&allok,1,MPI_INT,MPI_MIN,MPI_COMM_WORLD);
 if(rank==0)std::cout<<"PVIA_VSS_SELECTIVE_PROCESS_RESTART: "<<(allok?"PASS":"FAIL")<<" phase=DUPLICATE duplicate_delivery=REJECTED before_openings=PASS anchor_unchanged=PASS"<<std::endl;
 return allok==1;
}
} // namespace pvia
