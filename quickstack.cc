#include "quickstack.h"

#include <linux/version.h>
#include <asm/unistd.h>

#if defined(__i386__)
#define STACK_IP eip
#define STACK_SP esp
#elif defined(__x86_64__)
#define STACK_IP rip
#define STACK_SP rsp
#else
#error "unsupported cpu arch"
#endif

#if !defined(__linux__)
#error "unsupported os"
#endif

int target_pid= 0;
int debug_level= 2;
const char *debug_dir= "/usr/lib/debug";
stopper_symbol stopper[3] = {
  { "main", 0, 0 },
  { "start_thread", 0, 0},
  { "do_sigwait", 0, 0}
};
int num_stopper_symbol= 3;
int print_arg= 0;
int single_line= 0;
int basename_only= 0;
int max_ptrace_calls= 1000;

void print_log(const char *format, ...)
{
  struct timeval tv;
  time_t tt;
  struct tm *tm;
  gettimeofday(&tv, 0);
  tt= tv.tv_sec;
  tm= localtime(&tt);
  fprintf(stderr, "%04d-%02d-%02d %02d:%02d:%02d %06d: ",
    tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, tm->tm_hour,
    tm->tm_min, tm->tm_sec, tv.tv_usec);

  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fprintf(stderr, "\n");
}

static string dirname(const string& path) {
  return path.substr(0, path.find_last_of('/'));
}

static string basename(const string& path) {
  return path.substr(path.find_last_of('/') + 1);
}

static bool startwith(const string& fullstring, const string& starting)
{
  if(fullstring.length() >= starting.length()) {
    if(!fullstring.compare(0, starting.length(), starting))
      return true;
  } else {
    return false;
  }
  return false;
}

static bool endwith(const string& fullstring, const string& ending)
{
  if (fullstring.length() >= ending.length()) {
    return (0 == fullstring.compare (fullstring.length() - ending.length(), 
            ending.length(), ending));
  } else {
    return false;
  }
  return false;
}

static bool match_debug_file(const string& name, const char* file) {
  string ptr= file;
  string ending= ".debug";

  if(name.empty() || ptr.empty())
    return false;
  if(!startwith(ptr, name))
    return false;
  if(name.length() == ptr.length())
    return true;

  ptr= ptr.substr(name.length());
  if(!endwith(ptr, ending))
    return false;
  ptr= ptr.substr(0, ptr.length() - ending.length());
  char *work= (char*)ptr.c_str();
  while(*work) {
    if((*work >= 0 && *work <= 9) || *work == '.')
      work++;
    else
      return false;
  }
  return true;
}

static int get_user_regs(int pid, user_regs_struct& regs)
{
  int count = 100;
  while (1) {
    int e = ptrace(PTRACE_GETREGS, pid, 0, &regs);
    if (e != 0) {
      if (errno == ESRCH && count-- > 0) {
        /* i dont know why waitpid() does not work for threads */
        sched_yield();
        continue;
      }
      perror("ptrace(PTRACE_GETREGS)");
      return -1;
    }
    break;
  }
  return 0;
}

static char* find_debug_file(const char *stripped_file) {
  string path;
  path= debug_dir;
  path+= stripped_file;
  string dirname1= dirname(path);
  string name= basename(path);
  
  string real_debug_file;
  DIR *dp= opendir(dirname1.c_str());
  if(dp) {
    struct dirent *dent;
    do {
      dent = readdir(dp);
      if(dent) {
        if(dent->d_name[0] == '.')
          continue;
        if(match_debug_file(name, dent->d_name)) {
          real_debug_file= dirname1;
          real_debug_file+= "/";
          real_debug_file+= dent->d_name;
          break;
        }
      }
    }while(dent);
    closedir(dp);
  }
  return strdup(real_debug_file.c_str());
}


void bfd_handle::free_syms_if() {
  if(syms != NULL) {
    free(syms);
    syms= NULL;
  }
}

void bfd_handle::free_st_if() {
  if(st != NULL) {
    delete st;
    st= NULL;
  }
}

bool bfd_handle::has_debug() {
  return has_debug_symbols;
}

int bfd_handle::get_file_line(ulong addr, const char** file, const char **function, uint *lineno) {
  return bfd_find_nearest_line(abfd, dbgsec, syms, addr, file, function, lineno);
}

void bfd_handle::close_all() {
  free_st_if();
  free_syms_if();
  close();
  if(debug_file)
    free(debug_file);
}

void bfd_handle::init(const char *file = NULL) {
  abfd = bfd_openr(file ? file : filename, NULL);
  assert(abfd);
  bfd_check_format(abfd, bfd_object);
  assert((bfd_get_file_flags (abfd) & HAS_SYMS) != 0);
}

void bfd_handle::debug_init() {
  close();
  init(debug_file);
}

bfd* bfd_handle::get() {
  return abfd;
}

void bfd_handle::close() {
  if(abfd)
    bfd_close(abfd);
  abfd= NULL;
}

void load_stopper_symbols(symbol_table *sorted_st) {
  int matched_stopper= -1;
  for(symbol_table::symbols_type::iterator i = sorted_st->symbols.begin(); i != sorted_st->symbols.end(); i++) {
    int j=0;
    if(matched_stopper >= 0) {
      stopper[matched_stopper].addr_end= i->addr;
      matched_stopper= -1;
    }
    for(j=0; j < num_stopper_symbol; j++) {
      if(stopper[j].name == i->name) {
        stopper[j].addr_begin= i->addr;
        matched_stopper= j;
      }
    }
  }
}

void bfd_handle::load_symbols() {
  st= new symbol_table();
  load_debug_section_if();
  asection *const text_sec = bfd_get_section_by_name(abfd, ".text");
  if (text_sec) {
    st->text_vma = text_sec->vma;
    st->text_size = text_sec->size;
  }

  symcnt = bfd_read_minisymbols(abfd, 0, (void**)&syms, &size);
  if (!symcnt) {
    free_syms_if();
    symcnt = bfd_read_minisymbols(abfd, 1, (void**)&syms, &size);
    dynamic = 1;
  }

  asymbol *store = bfd_make_empty_symbol(abfd);
  assert(store);

  bfd_byte *p = (bfd_byte *)syms;
  bfd_byte *pend = p + symcnt * size;
  for (; p < pend; p += size) {
    asymbol *sym = 0;
    sym = bfd_minisymbol_to_symbol(abfd, dynamic, p, store);
    if ((sym->flags & BSF_FUNCTION) == 0) {
      continue;
    }
    symbol_info sinfo;
    bfd_get_symbol_info(abfd, sym, &sinfo);
    if (sinfo.type != 'T' && sinfo.type != 't' && sinfo.type != 'W' &&
      sinfo.type != 'w') {
      continue;
    }
    DBG(40, "%s %lx f=%x", sinfo.name, (long)sinfo.value,
      (int)sym->flags);

    if (startwith(sinfo.name, "__tcf"))
      continue;
    if (startwith(sinfo.name, "__tz"))
      continue;

    symbol_ent e;
    e.addr = sinfo.value;
    e.name = string(sinfo.name);
    st->symbols.push_back(e);
  }
  std::sort(st->symbols.begin(), st->symbols.end(), std::less<ulong>());
  load_stopper_symbols(st);
}

void bfd_handle::load_debug_section_if() {
  dbgsec = bfd_get_section_by_name(abfd, ".debug_info");
  if(!dbgsec) {
    debug_file= find_debug_file(filename);
    if(debug_file && strlen(debug_file) > 0) {
      DBG(3, "Reading debug file %s, original(%s) ..", debug_file, filename);
      debug_init();
      dbgsec = bfd_get_section_by_name(abfd, ".debug_info");
    }
  }
  if(dbgsec) {
    DBG(3, "has debug symbols on %s", debug_file ? debug_file : filename);
    has_debug_symbols= true;
  }else {
    DBG(1, "No debug symbols found on %s", filename);
    has_debug_symbols= false;
  }
}

static bool check_shlib(const std::string& fn)
{
  auto_fp fp(fopen(fn.c_str(), "r"));
  if (fp == 0) {
    return false;
  }
  elf_version(EV_CURRENT);
  Elf *elf = elf_begin(fileno(fp), ELF_C_READ, NULL);
  if (elf == 0) {
    return false;
  }
  bool found = false;
  ulong vaddr = 0;
  #if defined(__i386__)
  Elf32_Ehdr *const ehdr = elf32_getehdr(elf);
  Elf32_Phdr *const phdr = elf32_getphdr(elf);
  #else
  Elf64_Ehdr *const ehdr = elf64_getehdr(elf);
  Elf64_Phdr *const phdr = elf64_getphdr(elf);
  #endif
  const int num_phdr = ehdr->e_phnum;
  for (int i = 0; i < num_phdr; ++i) {
    #if defined(__i386__)
    Elf32_Phdr *const p = phdr + i;
    #else
    Elf64_Phdr *const p = phdr + i;
    #endif
    if (p->p_type == PT_LOAD && (p->p_flags & 1) != 0) {
      vaddr = p->p_vaddr;
      found = true;
      break;
    }
  }
  elf_end(elf);
  return vaddr == 0;
}

static void read_proc_map_ent(char *line, proc_info &pinfo,
  symbol_table_map *stmap)
{
  char *t1 = strchr(line, ' ');
  if (!t1) { return; }
  char *t2 = strchr(t1 + 1, ' ');
  if (!t2) { return; }
  char *t3 = strchr(t2 + 1, ' ');
  if (!t3) { return; }
  char *t4 = strchr(t3 + 1, ' ');
  if (!t4) { return; }
  char *t5 = strchr(t4 + 1, ' ');
  if (!t5) { return; }
  while (t5[1] == ' ') { ++t5; }
  char *t6 = strchr(t5 + 1, '\n');
  if (!t6) { return; }
  *t1 = *t2 = *t3 = *t4 = *t5 = *t6 = '\0';
  if (t2 - t1 == 5 && t2[-2] != 'x') {
    return;
  }
  ulong a0 = 0, a1 = 0;
  sscanf(line, "%lx-%lx", &a0, &a1);

  proc_map_ent e;

  e.addr_begin = a0;
  e.addr_size = a1 - a0;
  e.offset = atol(t2 + 1);
  e.path = std::string(t5 + 1);
  if (e.path == "[vdso]" || e.path == "[vsyscall]") {
    e.is_vdso = true;
  } else {
    e.stbl= stmap->get(e.path.c_str());
    if(!e.stbl) {
      bfd_handle *bh= NULL;
      bh= new bfd_handle(e.path.c_str());
      bh->init();
      bh->load_symbols();
      stmap->set(e.path.c_str(), bh->st);
      e.stbl= bh->st;
      e.stbl->bh= bh;
    }
    e.relative = check_shlib(e.path);
  }
  DBG(10, "%s: relative=%d addr_begin=%016lx", e.path.c_str(), (int)e.relative, e.addr_begin);
  pinfo.maps.push_back(e);
}

static void read_proc_maps(int pid, proc_info &pinfo, symbol_table_map *stmap) {
  char fn[PATH_MAX];
  char buf[4096];
  snprintf(fn, sizeof(fn), "/proc/%d/maps", pid);
  auto_fp fp(fopen(fn, "r"));
  if (fp == 0) {
    return;
  }
  while (fgets(buf, sizeof(buf), fp) != 0) {
    read_proc_map_ent(buf, pinfo, stmap);
  }
  std::sort(pinfo.maps.begin(), pinfo.maps.end(), std::less<ulong>());
}

static const symbol_ent *find_symbol(const symbol_table *st,
  ulong addr, bool& is_text_r, ulong& pos_r,
    ulong& offset_r)
{
  is_text_r = false;
  pos_r = 0;
  offset_r = 0;
  const symbol_table::symbols_type& ss = st->symbols;
  symbol_table::symbols_type::const_iterator j =
    std::upper_bound(ss.begin(), ss.end(), addr);
  if (j != ss.begin()) {
    --j;
  } else {
    return 0;
  }
  if (j == ss.end()) {
    return 0;
  }
  is_text_r = (*j >= st->text_vma && *j < st->text_vma + st->text_size);
  pos_r = j - ss.begin();
  offset_r = addr - *j;
  return &*j;
}

static bool pinfo_symbol_exists(const proc_info &pinfo, ulong addr)
{
  bool exists= false;
  proc_info::maps_type::const_iterator i = std::upper_bound(
    pinfo.maps.begin(), pinfo.maps.end(), addr);
  if (i != pinfo.maps.begin()) {
    --i;
  } else {
    i = pinfo.maps.end();
  }
  if (i == pinfo.maps.end()) {
    DBG(30, "%lx not found", addr);
  } else if (addr >= i->addr_begin + i->addr_size) {
    DBG(30, "%lx out of range [%lx %lx]", addr, i->addr_begin, i->addr_begin + i->addr_size);
  } else if (!i->stbl->bh) {
    DBG(30, "%lx no symbol found", addr);
  }else {
    exists= true;
  }
  return exists;
}

static const symbol_ent *pinfo_find_symbol(const proc_info &pinfo,
  ulong addr, ulong& offset_r, bfd_handle **bh_ptr, ulong& relative_addr)
{
  offset_r = 0;
  proc_info::maps_type::const_iterator i = std::upper_bound(
    pinfo.maps.begin(), pinfo.maps.end(), addr);
  if (i != pinfo.maps.begin()) {
    --i;
  } else {
    i = pinfo.maps.end();
  }
  if (i == pinfo.maps.end()) {
    DBG(30, "%lx not found", addr);
  } else if (addr >= i->addr_begin + i->addr_size) {
    DBG(30, "%lx out of range [%lx %lx]", addr, i->addr_begin, i->addr_begin + i->addr_size);
  } else if (!i->stbl || !i->stbl->bh) {
    DBG(30, "%lx no symbol found", addr);
    if (i->is_vdso) {
      offset_r = addr - i->addr_begin;
    }
  } else {
    ulong a = addr;
    if (i->relative) {
      a -= i->addr_begin;
      relative_addr= a;
    }
    ulong pos = 0;
    ulong offset = 0;
    bool is_text = false;
    const symbol_ent *const e = find_symbol(i->stbl, a, is_text, pos, offset);
    *bh_ptr= i->stbl->bh;
    if (e != 0 && is_text) {
      offset_r = offset;
      return e;
    } else {
    }
  }
  return 0;  
}

static bool is_stopper_addr(ulong addr) {
  bool is_stopper= false;
  int i;
  for(i= 0; i < num_stopper_symbol; i++) {
    if(stopper[i].addr_begin < addr && stopper[i].addr_end > addr) {
      is_stopper= true;
      break;
    }
  }
  return is_stopper;
}

static int get_stack_trace(int pid, proc_info& pinfo, uint maxlen,
  const user_regs_struct& regs, std::vector<ulong>& vals_r)
{
  ulong sp = regs.STACK_SP;
  ulong ip = regs.STACK_IP;
  vals_r.push_back(ip);
  uint i = 0;
  ulong next_likely_sp= 0;
  DBG(10, "top sp: %016lx", sp);
  if(is_stopper_addr(ip)) {
    DBG(3, "Matched stopper func.", 0);
    return 0;
  }

  for (i = 0; i < maxlen; ++i) {
    ulong retaddr = 0;
    retaddr = ptrace(PTRACE_PEEKDATA, pid, sp, 0);
    if (errno != 0) {
      DBG(3, "Got error %d on PTRACE_PEEKDATA", errno);
      break;
    }
    DBG(10, "Got addr %016lx", retaddr);
    sp += sizeof(long);
    if(retaddr == 0) {
      next_likely_sp= 0;
      continue;
    }
    if (pinfo.maps.empty()) {
      next_likely_sp= 0;
      continue;
    }
    if(next_likely_sp) {
      if(pinfo_symbol_exists(pinfo, retaddr)) {
        DBG(10, "Got next likely sp. %016lx", next_likely_sp);
        sp= next_likely_sp;
        next_likely_sp= 0;
      }
    }
    DBG(10, "Push addr %016lx", retaddr);
    vals_r.push_back(retaddr);
    if(is_stopper_addr(retaddr)) {
      DBG(3, "Matched stopper func.", 0);
      break;
    }
    if(retaddr > sp && retaddr < sp + 1000 * sizeof(long)) {
      next_likely_sp= retaddr;
    }else {
      next_likely_sp= 0;
    }
  }
  DBG(3, "Traced %d blocks.", i+1);
  return 0;
}

char *get_demangled_symbol(const char *symbol_name) {
  char *demangled= NULL;
  uint arg= DMGL_ANSI;
  if(print_arg) {
    arg |= DMGL_PARAMS;
    arg |= DMGL_TYPES;
  }
  demangled= cplus_demangle(symbol_name, arg);
  if (!demangled) {
    demangled= strdup(symbol_name);
  }
  return demangled;
}

void parse_stack_trace(const int pid, const proc_info &pinfo, const user_regs_struct &regs, const std::vector<ulong>& vals, size_t maxlen)
{
  char buf[128];
  uint rank= 1;
  std::string rstr;

  for (size_t i = 0; i < std::min(vals.size(), maxlen); ++i) {
  std::stringstream out;
  const char *file, *name;
  uint lineno;
  ulong addr= vals[i];
  ulong rel_addr= 0;
  ulong offset = 0;
  char *demangled;
  bfd_handle *bh;
  DBG(10, "addr: %016lx %ld %ld", addr, vals.size(), maxlen);
  const symbol_ent *e = pinfo_find_symbol(pinfo, addr, offset, &bh, rel_addr);
  if (e != 0) {
    if (offset != 0) {
      if(!single_line) {
      sprintf(buf, "#%02d  ", rank++);
      out << buf;
      sprintf(buf, "0x%016lx", addr);
      out << buf;
      out << " in ";
      demangled= get_demangled_symbol(e->name.c_str());
      out << demangled;
      free(demangled);
      if(!print_arg) {
        out << " ()";
      }
      if(bh->has_debug()) {
        int ret;
        ret= bh->get_file_line(rel_addr ? rel_addr : addr, &file, &name, &lineno);
        if(ret && file) {
          if(basename_only) {
            file= basename(file);
          }
          out << " from ";
          out << file;
          out << ":";
          out << lineno;
          out << "";
        }
      }else {
        if(basename_only) {
          file= basename(bh->filename);
        }else {
          file= bh->filename;
        }
        out << " from ";
        out << file;
      }
      std::cout << out.str() << std::endl;
      }else {
        if (!rstr.empty()) {
          rstr += ":";
        }
        demangled= get_demangled_symbol(e->name.c_str());
        rstr += demangled;
        free(demangled);
      }
    }
  }
  }
  if(!rstr.empty()) {
    std::cout << rstr << std::endl;
  }
}

void end_proc_maps(proc_info &pinfo) {
  for (proc_info::maps_type::iterator i = pinfo.maps.begin(); i != pinfo.maps.end(); ++i) {
  }
}

static int ptrace_attach_proc(int pid)
{
  if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
    perror("ptrace(PTRACE_ATTACH)");
    return -1;
  }
  int st = 0;
  const pid_t v = waitpid(pid, &st, __WALL | WUNTRACED);
  if (v < 0) {
    perror("waitpid");
    return -1;
  }
  return 0;
}

static int ptrace_detach_proc(int pid)
{
  if (ptrace(PTRACE_DETACH, pid, 0, 0) < 0) {
    perror("ptrace(PTRACE_DETACH)");
    return -1;
  }
  return 0;
}

int get_tgid(int target_pid) {
  int tgid= -1;
  char fn[PATH_MAX];
  char buf[4096];
  snprintf(fn, sizeof(fn), "/proc/%d/status", target_pid);
  auto_fp fp(fopen(fn, "r"));
  if (fp == 0) {
    return tgid;
  }
  while (fgets(buf, sizeof(buf), fp) != 0) {
    if(startwith(buf, "Tgid")) {
      sscanf(buf, "Tgid:%d", &tgid);
    }
  }
  return tgid;
}

void get_pids(int target_pid, std::vector<int>& pids_r) {
  char fn[PATH_MAX];
  bool target_pid_exists= false;
  snprintf(fn, sizeof(fn), "/proc/%d/task", target_pid);
  DIR *dp= opendir(fn);
  int tgid= get_tgid(target_pid);
  if(tgid <= 0) {
    fprintf(stderr, "Failed to get parent's process id!\n");
    goto err;
  }
  if(dp) {
    struct dirent *dent;
    do {
      dent = readdir(dp);
      if(dent) {
        if(dent->d_name[0] == '.')
          continue;
        int pid= atoi(dent->d_name);
        if(pid == target_pid) {
          target_pid_exists= true;
          continue;
        } else if (tgid != target_pid){
          continue;
        } else {
          pids_r.push_back(pid);
        }
      }
    }while(dent);
    closedir(dp);
  } else {
    fprintf(stderr, "Failed to access directory %s\n", fn);
    goto err;
  }
  if (!target_pid_exists) {
    fprintf(stderr, "Process id %d does not exist on %s\n", target_pid, fn);
    goto err;
  }
  std::sort(pids_r.begin(), pids_r.end());
  pids_r.push_back(target_pid);
  return;

err:
  exit(1);
}

void dump_stack(const vector<int>& pids)
{
  uint trace_length= 1000;
  symbol_table_map *stmap = new symbol_table_map();
  proc_info *pinfos= new proc_info[pids.size()];
  vector<ulong> *vals_sps= new vector<ulong>[pids.size()];
  user_regs_struct *regs= new user_regs_struct[pids.size()];
  bool *fails = new bool[pids.size()];

  for (size_t i = 0; i < pids.size(); ++i) {
    read_proc_maps(pids[i], pinfos[i], stmap);
  }

  for (size_t i = 0; i < pids.size(); ++i) {
    fails[i]= false;
    DBG(3, "Attaching process %d.", pids[i]);
    if (ptrace_attach_proc(pids[i]) != 0) {
      fails[i] = true;
    } else {
      if (get_user_regs(pids[i], regs[i]) != 0) {
        fails[i] = true;
      } else {
        if (max_ptrace_calls &&
          get_stack_trace(pids[i], pinfos[i], max_ptrace_calls, regs[i], vals_sps[i]) != 0) {
          fails[i] = true;
        }
      }
    }
    ptrace_detach_proc(pids[i]);
    DBG(3, "Detached process %d.", pids[i]);
  }

  for (size_t i = 0; i < pids.size(); ++i) {
    if(fails[i] == false) {
      if(single_line) {
        printf("%d  ", pids[i]);
      } else {
        printf("\nThread %ld (LWP %d):\n", pids.size() - i, pids[i]);
      }
      parse_stack_trace(pids[i], pinfos[i], regs[i], vals_sps[i], trace_length);
    }
  }
  delete[] fails;
  delete[] pinfos;
  delete[] vals_sps;
  delete[] regs;
  delete stmap;
}

#include <getopt.h>

struct option long_options[] =
{
  {"help", no_argument, 0, '?'},
  {"arg_print", no_argument, 0, 'a'},
  {"basename_only", no_argument, 0, 'b'},
  {"debug", required_argument, 0, 'd'},
  {"pid", required_argument, 0, 'p'},
  {"single_line", no_argument, 0, 's'},
  {"calls", required_argument, 0, 'c'},
  {0,0,0,0}
};

static void usage_exit() {
  printf("Usage: \n");
  printf(" quickstack [OPTIONS]\n\n");
  printf("Example: \n");
  printf(" quickstack -p `pidof mysqld`\n\n");
  printf("Options (short name):\n");
  printf(" -p, --pid=N                :Target process id\n");
  printf(" -d, --debug=N              :Debug level\n");
  printf(" -s, --single_line          :Printing call stack info into one line per process, instead of gdb-like output\n");
  printf(" -c, --calls=N              :Maximum ptrace call counts per process. Default is 1000\n");
  printf(" -b, --basename_only        :Suppressing printing directory name of the target source files, but printing basename only. This makes easier for reading.\n");
  exit(1);
}

static void get_options(int argc, char **argv) {
  int c, opt_ind= 0;
  while((c= getopt_long(argc, argv, "?absd:c:p:", long_options, &opt_ind)) != EOF)
  {
    switch(c) {
      case '?': usage_exit(); break;
      case 'a': print_arg= 1; break;
      case 'b': basename_only= 1; break;
      case 'c': max_ptrace_calls=atoi(optarg); break;
      case 'd': debug_level= atoi(optarg); break;
      case 'p': target_pid= atoi(optarg); break;
      case 's': single_line= 1; break;
      default: usage_exit(); break;
    }
  }
  if(!target_pid)
    usage_exit();
}

int main(int argc, char** argv) {
  if(argc <= 1) {
    usage_exit();
  }
  get_options(argc, argv);
  vector<int> pids;
  get_pids(target_pid, pids);
  dump_stack(pids);
  return 0;
}
