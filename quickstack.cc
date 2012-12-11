#include "quickstack.h"

#include <linux/version.h>
#include <asm/unistd.h>
#include <getopt.h>
#include <sys/mman.h>

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

const char *version = "0.10";
int target_pid = 0;
int debug_level = 2;
int debug_print_time_level = 10;
int frame_check = 0;
int flush_log = 3;
int timeout_seconds = 600;
bool lock_all = false;

const char *debug_dir = "/usr/lib/debug";
int *_attach_started = 0;
stopper_symbol stopper[3] = {
  {"main", 0, 0},
  {"start_thread", 0, 0},
  {"do_sigwait", 0, 0}
};
int num_stopper_symbol = 3;
string basic_libs[10] = {
  "ld-",
  "libaio.",
  "libc-",
  "libm-",
  "libdl-",
  "libpthread-",
  "librt-",
  "libgcc_",
  "libcrypt-",
  "libnss_" "libnsl_" "libstdc++"
};
int num_basic_libs = 10;
volatile sig_atomic_t shutdown_program = 0;
int print_arg = 0;
int single_line = 0;
int trace_multiple_procs = 0;
int basename_only = 0;
int max_ptrace_calls = 1000;
int max_frame_size = 16384 * sizeof(long);
const char *stack_out;
FILE *stack_out_fp;


static void set_shutdown(int)
{
  shutdown_program = 1;
}

static void init_signals()
{
  int signals[] = { SIGHUP, SIGINT, SIGTERM };
  for (uint i = 0; i < sizeof(signals) / sizeof(int); i++)
    signal(signals[i], set_shutdown);
  return;
}

static void ignore_signals()
{
  int signals[] = { SIGHUP, SIGINT, SIGTERM };
  for (uint i = 0; i < sizeof(signals) / sizeof(int); i++)
    signal(signals[i], SIG_IGN);
  return;
}

void print_log(int level, const char *format, ...)
{
  if (level < debug_print_time_level) {
    struct timeval tv;
    time_t tt;
    struct tm *tm;
    gettimeofday(&tv, 0);
    tt = tv.tv_sec;
    tm = localtime(&tt);
    fprintf(stdout, "%04d-%02d-%02d %02d:%02d:%02d %06ld: ",
	    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour,
	    tm->tm_min, tm->tm_sec, tv.tv_usec);
  } else {
    fprintf(stdout, "                            ");
  }

  va_list args;
  va_start(args, format);
  vfprintf(stdout, format, args);
  va_end(args);
  fprintf(stdout, "\n");
  if (flush_log >= level)
    fflush(stdout);
}

void print_stack(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  if (stack_out_fp) {
    vfprintf(stack_out_fp, format, args);
    fflush(stack_out_fp);
  } else {
    vfprintf(stdout, format, args);
    fflush(stdout);
  }
  va_end(args);
}

static string dirname(const string & path)
{
  return path.substr(0, path.find_last_of('/'));
}

static string basename(const string & path)
{
  return path.substr(path.find_last_of('/') + 1);
}

static bool startwith(const string & fullstring, const string & starting)
{
  if (fullstring.length() >= starting.length()) {
    if (!fullstring.compare(0, starting.length(), starting))
      return true;
  } else {
    return false;
  }
  return false;
}

static bool endwith(const string & fullstring, const string & ending)
{
  if (fullstring.length() >= ending.length()) {
    return (0 ==
	    fullstring.compare(fullstring.length() - ending.length(),
			       ending.length(), ending));
  } else {
    return false;
  }
  return false;
}

static int is_pid_stopped(int pid)
{
  FILE *status_file;
  char buf[100];
  int retval = 0;

  snprintf(buf, sizeof(buf), "/proc/%d/status", (int) pid);
  status_file = fopen(buf, "r");
  if (status_file != NULL) {
    int have_state = 0;
    while (fgets(buf, sizeof(buf), status_file)) {
      buf[strlen(buf) - 1] = '\0';
      if (strncmp(buf, "State:", 6) == 0) {
	have_state = 1;
	break;
      }
    }
    if (have_state && strstr(buf, "T") != NULL) {
      DBG(9, "Process %d %s", pid, buf);
      retval = 1;
    }
    fclose(status_file);
  }
  return retval;
}

static bool match_debug_file(const string & name, const char *file)
{
  string ptr = file;
  string ending = ".debug";

  if (name.empty() || ptr.empty())
    return false;
  if (!startwith(ptr, name))
    return false;
  if (name.length() == ptr.length())
    return true;

  ptr = ptr.substr(name.length());
  if (!endwith(ptr, ending))
    return false;
  ptr = ptr.substr(0, ptr.length() - ending.length());
  char *work = (char *) ptr.c_str();
  while (*work) {
    if ((*work >= 0 && *work <= 9) || *work == '.')
      work++;
    else
      return false;
  }
  return true;
}

static int get_user_regs(int pid, user_regs_struct & regs)
{
  int count = 100;
  while (1) {
    int e = ptrace(PTRACE_GETREGS, pid, 0, &regs);
    if (e != 0) {
      if (errno == ESRCH && count-- > 0) {
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

static char *find_debug_file(const char *stripped_file)
{
  string path;
  path = debug_dir;
  path += stripped_file;
  string dirname1 = dirname(path);
  string name = basename(path);

  string real_debug_file;
  DIR *dp = opendir(dirname1.c_str());
  if (dp) {
    struct dirent *dent;
    do {
      dent = readdir(dp);
      if (dent) {
	if (dent->d_name[0] == '.')
	  continue;
	if (match_debug_file(name, dent->d_name)) {
	  real_debug_file = dirname1;
	  real_debug_file += "/";
	  real_debug_file += dent->d_name;
	  break;
	}
      }
    }
    while (dent);
    closedir(dp);
  }
  return strdup(real_debug_file.c_str());
}


void bfd_handle::free_syms_if()
{
  if (syms != NULL) {
    free(syms);
    syms = NULL;
  }
}

void bfd_handle::free_st_if()
{
  if (st != NULL) {
    delete st;
    st = NULL;
  }
}

bool bfd_handle::has_debug()
{
  return has_debug_symbols;
}

int bfd_handle::get_file_line(ulong addr, const char **file,
			      const char **function, uint * lineno)
{
  return bfd_find_nearest_line(abfd, dbgsec, syms, addr - 1, file,
			       function, lineno);
}

void bfd_handle::close_all()
{
  free_st_if();
  free_syms_if();
  close();
  if (debug_file)
    free(debug_file);
}

void bfd_handle::init(const char *file = NULL)
{
  abfd = bfd_openr(file ? file : filename, NULL);
  if (!abfd) {
    fprintf(stderr, "Failed at bfd_openr! %s\n", file ? file : filename);
    exit(1);
  }
  bfd_check_format(abfd, bfd_object);
  assert((bfd_get_file_flags(abfd) & HAS_SYMS) != 0);
}

void bfd_handle::debug_init()
{
  close();
  init(debug_file);
}

bfd *bfd_handle::get()
{
  return abfd;
}

void bfd_handle::close()
{
  if (abfd)
    bfd_close(abfd);
  abfd = NULL;
}

void
load_stopper_symbols(symbol_table * sorted_st, bool relative,
		     ulong addr_begin)
{
  int matched_stopper = -1;
  for (symbol_table::symbols_type::iterator i =
       sorted_st->symbols.begin(); i != sorted_st->symbols.end(); i++) {
    int j = 0;
    if (matched_stopper >= 0) {
      stopper[matched_stopper].addr_end = i->addr;
      if (relative) {
	stopper[matched_stopper].addr_end += addr_begin;
      }
      matched_stopper = -1;
    }
    for (j = 0; j < num_stopper_symbol; j++) {
      if (stopper[j].name == i->name) {
	stopper[j].addr_begin = i->addr;
	if (relative) {
	  stopper[j].addr_begin += addr_begin;
	}
	matched_stopper = j;
      }
    }
  }
}

void bfd_handle::load_symbols(bool relative, ulong addr_begin)
{
  st = new symbol_table();
  load_debug_section_if();
  asection *const text_sec = bfd_get_section_by_name(abfd, ".text");
  if (text_sec) {
    st->text_vma = text_sec->vma;
    st->text_size = text_sec->size;
  }

  symcnt = bfd_read_minisymbols(abfd, 0, (void **) &syms, &size);
  if (!symcnt) {
    free_syms_if();
    symcnt = bfd_read_minisymbols(abfd, 1, (void **) &syms, &size);
    dynamic = 1;
  }

  asymbol *store = bfd_make_empty_symbol(abfd);
  assert(store);

  bfd_byte *p = (bfd_byte *) syms;
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
    DBG(40, "%s %lx f=%x", sinfo.name, (long) sinfo.value,
	(int) sym->flags);

    if (startwith(sinfo.name, "__tcf"))
      continue;
    if (startwith(sinfo.name, "__tz"))
      continue;

    symbol_ent e;
    e.addr = sinfo.value;
    e.name = string(sinfo.name);
    st->symbols.push_back(e);
  }
  std::sort(st->symbols.begin(), st->symbols.end(),
	    std::less < ulong > ());
  load_stopper_symbols(st, relative, addr_begin);
}

void bfd_handle::load_debug_section_if()
{
  dbgsec = bfd_get_section_by_name(abfd, ".debug_info");
  if (!dbgsec) {
    debug_file = find_debug_file(filename);
    if (debug_file && strlen(debug_file) > 0) {
      DBG(3, "Reading debug file %s, original(%s) ..", debug_file,
	  filename);
      debug_init();
      dbgsec = bfd_get_section_by_name(abfd, ".debug_info");
    }
  }
  if (dbgsec) {
    DBG(3, "has debug symbols on %s", debug_file ? debug_file : filename);
    has_debug_symbols = true;
  } else {
    DBG(1, "No debug symbols found on %s", filename);
    has_debug_symbols = false;
  }
}

static bool check_shlib(const std::string & fn)
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
      break;
    }
  }
  elf_end(elf);
  return vaddr == 0;
}

static bool file_exists(const char *filename)
{
  if (FILE * file = fopen(filename, "r")) {
    fclose(file);
    return true;
  }
  return false;
}

static bool has_exec_permission(const char *filename)
{
  struct stat results;
  stat(filename, &results);
  if (results.st_mode & S_IXUSR)
    return true;
  return false;
}

static void
read_proc_map_ent(char *line, proc_info & pinfo, symbol_table_map * stmap)
{
  bool delete_marked = false;
  char *t1 = strchr(line, ' ');
  if (!t1) {
    return;
  }
  char *t2 = strchr(t1 + 1, ' ');
  if (!t2) {
    return;
  }
  char *t3 = strchr(t2 + 1, ' ');
  if (!t3) {
    return;
  }
  char *t4 = strchr(t3 + 1, ' ');
  if (!t4) {
    return;
  }
  char *t5 = strchr(t4 + 1, ' ');
  if (!t5) {
    return;
  }
  while (t5[1] == ' ') {
    ++t5;
  }
  char *t6 = strchr(t5 + 1, '\n');
  char *t7 = strchr(t5 + 1, ' ');
  if (!t6) {
    return;
  }
  *t1 = *t2 = *t3 = *t4 = *t5 = *t6 = '\0';
  if (t7) {
    if (startwith(std::string(t7), " (deleted")) {
      delete_marked = true;
    }
    *t7 = '\0';
  }
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
  if (e.path.empty()) {
    return;
  } else if (e.path == "[vdso]") {
    e.is_vdso = true;
  } else if (startwith(e.path, "[")) {
    return;
  } else {
    if (delete_marked && !file_exists(e.path.c_str()))
      return;
    if (!has_exec_permission(e.path.c_str()))
      return;
    e.stbl = stmap->get(e.path.c_str());
    e.relative = check_shlib(e.path);
    if (!e.stbl) {
      bfd_handle *bh = NULL;
      bh = new bfd_handle(e.path.c_str());
      bh->init();
      bh->load_symbols(e.relative, e.addr_begin);
      stmap->set(e.path.c_str(), bh->st);
      e.stbl = bh->st;
      e.stbl->bh = bh;
    }
  }
  DBG(10, "%s: relative=%d addr_begin=%016lx",
      e.path.c_str(), (int) e.relative, e.addr_begin);
  pinfo.maps.push_back(e);
}

static void
read_proc_maps(int pid, proc_info & pinfo, symbol_table_map * stmap)
{
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
  std::sort(pinfo.maps.begin(), pinfo.maps.end(), std::less < ulong > ());
}

static const symbol_ent *find_symbol(const symbol_table * st,
				     ulong addr, bool & is_text_r,
				     ulong & pos_r, ulong & offset_r)
{
  is_text_r = false;
  pos_r = 0;
  offset_r = 0;
  const symbol_table::symbols_type & ss = st->symbols;
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

static bool match_basic_lib(const string & path)
{
  for (int i = 0; i < num_basic_libs; i++) {
    if (startwith(basename(path), basic_libs[i])) {
      return true;
    }
  }
  return false;
}

static int pinfo_symbol_exists(const proc_info & pinfo, ulong addr)
{
  /* 0: not exists, 1: core library, 2: others */
  int symbol_type = 0;
  proc_info::maps_type::const_iterator i =
      std::upper_bound(pinfo.maps.begin(), pinfo.maps.end(), addr);
  if (i != pinfo.maps.begin()) {
    --i;
  } else {
    i = pinfo.maps.end();
  }
  if (i == pinfo.maps.end()) {
    DBG(30, "%lx not found", addr);
  } else if (addr >= i->addr_begin + i->addr_size) {
    DBG(30, "%lx out of range [%lx %lx]", addr, i->addr_begin,
	i->addr_begin + i->addr_size);
  } else if (!i->stbl || !i->stbl->bh) {
    DBG(30, "%lx no symbol found", addr);
  } else {
    symbol_type = 2;
    if (match_basic_lib(i->path)) {
      symbol_type = 1;
      DBG(10, "Matched basic libs %s", i->path.c_str());
    }
  }
  return symbol_type;
}

static const symbol_ent *pinfo_find_symbol(const proc_info & pinfo,
					   ulong addr, ulong & offset_r,
					   bfd_handle ** bh_ptr,
					   ulong & relative_addr,
					   bool ignore_basic_libs = false)
{
  offset_r = 0;
  proc_info::maps_type::const_iterator i =
      std::upper_bound(pinfo.maps.begin(), pinfo.maps.end(), addr);
  if (i != pinfo.maps.begin()) {
    --i;
  } else {
    i = pinfo.maps.end();
  }
  if (i == pinfo.maps.end()) {
    DBG(30, "%lx not found", addr);
  } else if (addr >= i->addr_begin + i->addr_size) {
    DBG(30, "%lx out of range [%lx %lx]", addr, i->addr_begin,
	i->addr_begin + i->addr_size);
  } else if (!i->stbl || !i->stbl->bh) {
    DBG(30, "%lx no symbol found", addr);
    if (i->is_vdso) {
      offset_r = addr - i->addr_begin;
    }
  } else {
    if (ignore_basic_libs) {
      if (match_basic_lib(i->path)) {
	DBG(10, "Matched basic libs2 %s", i->path.c_str());
	return 0;
      }
    }
    ulong a = addr;
    if (i->relative) {
      a -= i->addr_begin;
      relative_addr = a;
    }
    ulong pos = 0;
    ulong offset = 0;
    bool is_text = false;
    const symbol_ent *const e =
	find_symbol(i->stbl, a, is_text, pos, offset);
    *bh_ptr = i->stbl->bh;
    if (e != 0 && is_text) {
      offset_r = offset;
      return e;
    } else {
    }
  }
  return 0;
}

static bool is_stopper_addr(ulong addr)
{
  bool is_stopper = false;
  int i;
  for (i = 0; i < num_stopper_symbol; i++) {
    if (stopper[i].addr_begin < addr && stopper[i].addr_end > addr) {
      is_stopper = true;
      break;
    }
  }
  return is_stopper;
}


static int
get_stack_trace(int pid, proc_info & pinfo, uint maxlen,
		const user_regs_struct & regs,
		std::vector < ulong > &vals_r)
{
  uint i = 0;
  // candidate for the next stack address
  ulong next_likely_sp = 0;
  // address to start re-scanning if getting invalid addresses
  ulong rollback_addr = 0;
  bool matched_top_sp = false;
  uint error_count = 0;
  uint n_frames = 0;
  uint n_scanned = 0;
  bool top_addr_is_user_func = 0;
  uint n_scanned_from_last_frame = 0;
  bool sp_jumped = false;

  ulong sp = regs.STACK_SP;
  ulong top_addr = regs.STACK_IP;
  ulong top_sp = sp;
  // needs special care for second addr
  ulong second_addr = 0;

  DBG(10, "Top addr %016lx", top_addr);
  DBG(10, "Top sp: %016lx", sp);

  vals_r.push_back(top_addr);
  n_frames++;
  if (is_stopper_addr(top_addr)) {
    DBG(3, "Matched stopper func.", 0);
    return 0;
  }

  if (pinfo_symbol_exists(pinfo, top_addr) == 2) {
    DBG(10, "Top addr is user func.", "");
    top_addr_is_user_func = true;
  }

  for (i = 0; i < maxlen; ++i) {
    ulong retaddr = 0;
    retaddr = ptrace(PTRACE_PEEKDATA, pid, sp, 0);
    if (errno != 0) {
      DBG(3, "Got error %d on PTRACE_PEEKDATA", errno);
      break;
    }
    n_scanned++;
    n_scanned_from_last_frame++;
    DBG(10, "SP %016lx", sp);
    DBG(10, "Got addr %016lx", retaddr);
    DBG(10, "Frame count %d", n_frames);
    sp += sizeof(long);
    if (next_likely_sp < sp) {
      next_likely_sp = 0;
    }
    if (retaddr == 0) {
      continue;
    }

    if (retaddr == top_sp) {
      DBG(10, "Addr matched top sp %016lx. "
	  "Dropping previously scanned blocks.", retaddr);
      matched_top_sp = true;
      if (n_frames >= 2) {
	vals_r.clear();
	vals_r.push_back(top_addr);
	n_scanned_from_last_frame = 0;
	n_frames = 1;
	sp_jumped = false;
      }
    }
    if (pinfo.maps.empty()) {
      continue;
    }
    int symbol_type = pinfo_symbol_exists(pinfo, retaddr);
    DBG(10, "Got symbol type %d", symbol_type);

    if (symbol_type) {
      error_count = 0;
      if (frame_check && symbol_type == 2 &&
	  n_scanned_from_last_frame >= 3 &&
	  ((!matched_top_sp && n_scanned_from_last_frame >= 10) ||
	   n_frames >= 2 || top_addr_is_user_func) && !next_likely_sp) {
	DBG(10, "Non target addr %016lx", retaddr);
      } else {
	if (next_likely_sp) {
	  DBG(10, "Jumping to next likely sp %016lx", next_likely_sp);
	  rollback_addr = sp - sizeof(long);
	  sp_jumped = true;
	  sp = next_likely_sp;
	}
	n_frames++;
	n_scanned_from_last_frame = 0;
	DBG(10, "Pushed addr %016lx", retaddr);
	vals_r.push_back(retaddr);
	next_likely_sp = 0;
	if (n_frames == 2 && !second_addr) {
	  DBG(10, " This is second frame addr.");
	  second_addr = retaddr;
	}
      }
    } else {
      error_count++;
      if (retaddr >= sp + sizeof(long) && retaddr < sp + max_frame_size) {
	DBG(10, "retaddr is in sp range", "");
	error_count = 0;
      } else if (frame_check && error_count >= 2) {
	next_likely_sp = 0;
	if (rollback_addr && sp_jumped) {
	  DBG(10, "Previous next likely sp was invalid."
	      "Scanning from %016lx", rollback_addr);
	  sp = rollback_addr;
	  rollback_addr = 0;
	  //n_scanned= n_scanned - error_count;
	  error_count = 0;
	  sp_jumped = false;
	  if (!matched_top_sp || n_frames >= 2) {
	    vals_r.clear();
	    vals_r.push_back(top_addr);
	    n_scanned_from_last_frame = 0;
	  }
	  n_frames = 1;
	  continue;
	}
      }
    }
    if (is_stopper_addr(retaddr)) {
      DBG(3, "Matched stopper func.", 0);
      if (vals_r.size() == 2 && second_addr && second_addr != retaddr) {
	DBG(10, "Putting second_addr.");
	vals_r.pop_back();
	vals_r.push_back(second_addr);
	vals_r.push_back(retaddr);
      }
      break;
    }
    bool do_rollback = false;
    if (retaddr >= sp + sizeof(long) && retaddr < sp + max_frame_size) {
      if (next_likely_sp && n_frames <= 2) {
	DBG(10, "Finding Next Likely sp consecutive times. "
	    "Previously pushed addr was invalid");
	do_rollback = true;
      }
      next_likely_sp = retaddr;
      if (retaddr > sp + sizeof(long)) {
	sp_jumped = true;
      } else {
	sp_jumped = false;
      }
      DBG(10, "Next Likely SP: %016lx", next_likely_sp);
    }
    if (sp_jumped && frame_check) {
      if (n_scanned_from_last_frame >= 5 && n_frames >= 3) {
	DBG(10,
	    "Scanned %d blocks from the last frame. This is invalid.",
	    n_scanned_from_last_frame);
	do_rollback = true;
      } else if (symbol_type == 1 && n_frames >= 3
		 && !is_stopper_addr(retaddr)) {
	DBG(10,
	    "Matched core lib symbol type in the middle of stack frames. This is invalid.");
	do_rollback = true;
      }
    }
    if (do_rollback) {
      if (rollback_addr) {
	DBG(10, "Scanning from %016lx", rollback_addr);
	sp = rollback_addr;
	rollback_addr = 0;
      }
      vals_r.clear();
      vals_r.push_back(top_addr);
      n_scanned_from_last_frame = 0;
      n_frames = 1;
      sp_jumped = false;
    }
  }
  DBG(3, "Scanned %d blocks.", n_scanned);
  return 0;
}

char *get_demangled_symbol(const char *symbol_name)
{
  char *demangled = NULL;
  uint arg = DMGL_ANSI;
  if (print_arg) {
    arg |= DMGL_PARAMS;
    arg |= DMGL_TYPES;
  }
  demangled = cplus_demangle(symbol_name, arg);
  if (!demangled) {
    demangled = strdup(symbol_name);
  }
  return demangled;
}

void
parse_stack_trace(const int pid, const proc_info & pinfo,
		  const user_regs_struct & regs,
		  const std::vector < ulong > &vals_sps, size_t maxlen)
{
  char buf[128];
  uint rank = 1;
  std::string rstr;

  for (size_t i = 0; i < std::min(vals_sps.size(), maxlen); ++i) {
    std::stringstream out;
    const char *file, *name;
    uint lineno;
    ulong addr = vals_sps[i];
    ulong rel_addr = 0;
    ulong offset = 0;
    char *demangled;
    bfd_handle *bh;
    DBG(11, "addr: %016lx %ld %ld", addr, vals_sps.size(), maxlen);
    bool ignore_basic_libs = true;
    if (i == 0 || i == std::min(vals_sps.size(), maxlen) - 1) {
      ignore_basic_libs = false;
    }
    const symbol_ent *e = pinfo_find_symbol(pinfo,
					    addr, offset, &bh, rel_addr,
					    ignore_basic_libs);
    if (e != 0) {
      if (offset != 0) {
	if (!single_line) {
	  sprintf(buf, "#%02d  ", rank++);
	  out << buf;
	  sprintf(buf, "0x%016lx", addr);
	  out << buf;
	  out << " in ";
	  demangled = get_demangled_symbol(e->name.c_str());
	  out << demangled;
	  free(demangled);
	  if (!print_arg) {
	    out << " ()";
	  }
	  if (bh->has_debug()) {
	    int ret;
	    ret = bh->get_file_line(rel_addr ? rel_addr : addr,
				    &file, &name, &lineno);
	    if (ret && file) {
	      if (basename_only) {
		file = basename(file);
	      }
	      out << " from ";
	      out << file;
	      out << ":";
	      out << lineno;
	      out << "";
	    }
	  } else {
	    if (basename_only) {
	      file = basename(bh->filename);
	    } else {
	      file = bh->filename;
	    }
	    out << " from ";
	    out << file;
	  }
	  print_stack("%s\n", out.str().c_str());
	} else {
	  if (!rstr.empty()) {
	    rstr += ":";
	  }
	  demangled = get_demangled_symbol(e->name.c_str());
	  rstr += demangled;
	  free(demangled);
	}
      }
    }
  }
  if (!rstr.empty()) {
    print_stack("%s\n", rstr.c_str());
  }
}


static int ptrace_attach_proc(int pid)
{
  if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0) {
    if (errno == ESRCH) {
      DBG(11, "No such process: %d", pid);
      return ESRCH;
    } else {
      perror("ptrace(PTRACE_ATTACH)");
      return -1;
    }
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
  if (ptrace(PTRACE_DETACH, pid, 0, 0) != 0) {
    perror("ptrace(PTRACE_DETACH)");
    return -1;
  }
  return 0;
}

int get_tgid(int target_pid)
{
  int tgid = -1;
  char fn[PATH_MAX];
  char buf[4096];
  snprintf(fn, sizeof(fn), "/proc/%d/status", target_pid);
  auto_fp fp(fopen(fn, "r"));
  if (fp == 0) {
    return tgid;
  }
  while (fgets(buf, sizeof(buf), fp) != 0) {
    if (startwith(buf, "Tgid")) {
      sscanf(buf, "Tgid:%d", &tgid);
    }
  }
  return tgid;
}

void get_pids(int target_pid, std::vector < int >&pids_r)
{
  char fn[PATH_MAX];
  bool target_pid_exists = false;
  snprintf(fn, sizeof(fn), "/proc/%d/task", target_pid);
  DIR *dp = opendir(fn);
  int tgid = get_tgid(target_pid);
  if (tgid <= 0) {
    fprintf(stderr, "Failed to get parent's process id!\n");
    exit(1);
  }
  if (dp) {
    struct dirent *dent;
    do {
      dent = readdir(dp);
      if (dent) {
	if (dent->d_name[0] == '.')
	  continue;
	int pid = atoi(dent->d_name);
	if (pid == target_pid) {
	  target_pid_exists = true;
	  continue;
	} else if (tgid != target_pid) {
	  continue;
	} else {
	  pids_r.push_back(pid);
	}
      }
    }
    while (dent);
    closedir(dp);
  } else {
    fprintf(stderr, "Failed to access directory %s\n", fn);
    exit(1);
  }
  if (!target_pid_exists) {
    fprintf(stderr, "Process id %d does not exist on %s\n", target_pid,
	    fn);
    exit(1);
  }
  std::sort(pids_r.begin(), pids_r.end());
  pids_r.push_back(target_pid);
  return;
}

static double timediff(struct timeval tv0, struct timeval tv1)
{
  return (tv1.tv_sec - tv0.tv_sec) * 1e+3 +
      (double) ((double) tv1.tv_usec * 1e-3 - (double) tv0.tv_usec * 1e-3);
}

void print_trace_report(proc_info * pinfos, const vector < int >&pids)
{
  int slowest_pid = 0;
  double slowest_time = -1;
  double sum_time = 0;

  for (uint i = 0; i < pids.size(); i++) {
    if (pinfos[i].stall_time > slowest_time) {
      slowest_pid = pids[i];
      slowest_time = pinfos[i].stall_time;
    }
    sum_time += pinfos[i].stall_time;
  }
  // Traced time == hangup time
  DBG(1, "Total Traced Time: %6.3f milliseconds", sum_time);
  DBG(1, "Average Traced Time Per LWP: %6.3f milliseconds",
      (double) sum_time / pids.size());
  DBG(1, "Longest Traced LWP: LWP %d, %6.3f milliseconds",
      slowest_pid, slowest_time);
}

void
attach_and_dump_all(const vector < int >&pids, proc_info * pinfos,
		    vector < ulong > *vals_sps, user_regs_struct * regs,
		    bool * fails, bool lock_main)
{
  for (size_t i = 0; i < pids.size(); ++i) {

    if (lock_main && pids[i] == target_pid) {
      if (get_user_regs(pids[i], regs[i]) != 0) {
	fails[i] = true;
      } else {
	if (max_ptrace_calls &&
	    get_stack_trace(pids[i], pinfos[i],
			    max_ptrace_calls, regs[i], vals_sps[i]) != 0) {
	  fails[i] = true;
	}
      }
      continue;
    }

    fails[i] = false;
    // do not attach if pid does not exist
    if (kill(pids[i], 0) != 0) {
      DBG(11, "kill(0) failed (pid not exist): %d", pids[i]);
      fails[i] = true;
      continue;
    }
    if (is_pid_stopped(pids[i])) {
      DBG(3, "PID %d stops. Skipping tracing the pid.", pids[i]);
    }
    DBG(3, "Attaching process %d.", pids[i]);
    gettimeofday(&pinfos[i].tv_start, 0);
    int rc = ptrace_attach_proc(pids[i]);
    if (rc != 0) {
      fails[i] = true;
    } else {
      if (get_user_regs(pids[i], regs[i]) != 0) {
	fails[i] = true;
      } else {
	if (max_ptrace_calls &&
	    get_stack_trace(pids[i], pinfos[i],
			    max_ptrace_calls, regs[i], vals_sps[i]) != 0) {
	  fails[i] = true;
	}
      }
    }
    if (rc != ESRCH) {
      ptrace_detach_proc(pids[i]);
      gettimeofday(&pinfos[i].tv_end, 0);
      pinfos[i].stall_time =
	  timediff(pinfos[i].tv_start, pinfos[i].tv_end);
      DBG(3, "Detached process %d", pids[i]);
      DBG(3, "Tracing duration at LWP %d was "
	  "%7.3f milliseconds\n", pids[i], pinfos[i].stall_time);
    }
    if (shutdown_program) {
      DBG(1, "Got termination signal");
      break;
    }
  }
}

void
attach_and_dump_lock_all(const vector < int >&pids, proc_info * pinfos,
			 vector < ulong > *vals_sps,
			 user_regs_struct * regs, bool * fails)
{
  struct timeval tv_start, tv_end;
  DBG(1, "Attaching main process %d, locking all.", target_pid);
  gettimeofday(&tv_start, 0);
  int rc = ptrace_attach_proc(target_pid);
  if (rc) {
    DBG(1, "Failed to attach main process.");
    if (rc != ESRCH)
      ptrace_detach_proc(target_pid);
    exit(1);
  }
  attach_and_dump_all(pids, pinfos, vals_sps, regs, fails, true);
  ptrace_detach_proc(target_pid);
  gettimeofday(&tv_end, 0);
  DBG(1, "Detached main process %d", target_pid);
  DBG(3, "Tracing duration at main process %d was "
      "%7.3f milliseconds\n", target_pid, timediff(tv_start, tv_end));
}


void dump_stack(const vector < int >&pids)
{
  uint trace_length = 1000;
  symbol_table_map *stmap = new symbol_table_map();
  proc_info *pinfos = new proc_info[pids.size()];
  vector < ulong > *vals_sps = new vector < ulong >[pids.size()];
  user_regs_struct *regs = new user_regs_struct[pids.size()];
  bool *fails = new bool[pids.size()];

  DBG(1, "Reading process symbols..");
  for (size_t i = 0; i < pids.size(); ++i) {
    if (!trace_multiple_procs && i >= 1) {
      pinfos[i] = pinfos[0];
    } else {
      read_proc_maps(pids[i], pinfos[i], stmap);
    }
  }

  if (is_pid_stopped(target_pid)) {
    DBG(1, "Target PID %d stops. Consider starting "
	"the process with kill -CONT. Exiting without tracing.",
	target_pid);
    exit(1);
  }
  DBG(1, "Gathering stack traces..");
  *_attach_started = 1;

  if (lock_all)
    attach_and_dump_lock_all(pids, pinfos, vals_sps, regs, fails);
  else
    attach_and_dump_all(pids, pinfos, vals_sps, regs, fails, false);

  DBG(1, "Printing stack traces..");
  print_trace_report(pinfos, pids);

  if (stack_out) {
    stack_out_fp = fopen(stack_out, "w");
  }

  for (size_t i = 0; i < pids.size(); ++i) {
    if (fails[i] == false) {
      if (single_line) {
	print_stack("%d  ", pids[i]);
      } else {
	print_stack("\nThread %ld (LWP %d):\n", pids.size() - i, pids[i]);
      }
      parse_stack_trace(pids[i], pinfos[i],
			regs[i], vals_sps[i], trace_length);
    }
  }
  if (stack_out_fp) {
    fclose(stack_out_fp);
    stack_out_fp = NULL;
  }
  delete[]fails;
  delete[]pinfos;
  delete[]vals_sps;
  delete[]regs;
  delete stmap;
}

struct option long_options[] = {
  {"?", no_argument, 0, '?'},
  {"help", no_argument, 0, 'h'},
  {"version", no_argument, 0, 'v'},
  {"arg_print", no_argument, 0, 'a'},
  {"basename_only", no_argument, 0, 'b'},
  {"debug", required_argument, 0, 'd'},
  {"debug_print_time_level", required_argument, 0, 't'},
  {"pid", required_argument, 0, 'p'},
  {"single_line", no_argument, 0, 's'},
  {"calls", required_argument, 0, 'c'},
  {"frame_check", no_argument, 0, 'f'},
  {"stack_out", required_argument, 0, 'o'},
  {"multiple_targets", required_argument, 0, 'm'},
  {"flush_log", required_argument, 0, 'w'},
  {"timeout_seconds", required_argument, 0, 'k'},
  {"lock_all", no_argument, 0, 'l'},
  {0, 0, 0, 0}
};

static void show_version()
{
  printf("quickstack version %s\n", version);
}

static void version_exit()
{
  show_version();
  exit(1);
}

static void usage_exit()
{
  show_version();
  printf("Usage: \n");
  printf(" quickstack [OPTIONS]\n\n");
  printf("Example: \n");
  printf(" quickstack -p `pidof mysqld`\n\n");
  printf("Options (short name):\n");
  printf(" -p, --pid=N                    :Target process id\n");
  printf(" -d, --debug=N                  :Debug level\n");
  printf
      (" -s, --single_line              :Printing call stack info into one line per process, instead of gdb-like output\n");
  printf
      (" -c, --calls=N                  :Maximum ptrace call counts per process. Default is 1000\n");
  printf
      (" -b, --basename_only            :Suppressing printing directory name of the target source files, but printing basename only. This makes easier for reading.\n");
  printf
      (" -f, --frame_check              :Checking frame pointers on non-standard libraries.\n");
  printf
      (" -o, --stack_out=f              :Writing stack traces to this file. Default is STDOUT.\n");
  printf
      (" -t, --debug_print_time_level=N :Suppressing printing timestamp if debug level is higher than N. This is for performance reason and default level (10) should be fine in most of cases.\n");
  printf
      (" -f, --multipe_targets=[0|1]    :Set 1 if tracing multiple different processes at one time\n");
  printf
      (" -w, --flush_log=N              :Flushing every log output if log level is equal or under N\n");
  printf
      (" -k, --timeout_seconds=N        :Terminates quickstack if exceeding N seconds. Default is 600 seconds\n");
  printf
      (" -l, --lock_all                 :Locking main process (given by --pid) during parsing all other processes. This will lock the whole process during taking all stack traces, so stall time is slightly increased, but will give more accurate results.\n");
  exit(1);
}

static void get_options(int argc, char **argv)
{
  int c, opt_ind = 0;
  while ((c = getopt_long(argc, argv, "?absflvw:k:d:c:t:p:o:",
			  long_options, &opt_ind)) != EOF) {
    switch (c) {
    case '?':
      usage_exit();
      break;
    case 'h':
      usage_exit();
      break;
    case 'a':
      print_arg = 1;
      break;
    case 'b':
      basename_only = 1;
      break;
    case 'c':
      max_ptrace_calls = atoi(optarg);
      break;
    case 'd':
      debug_level = atoi(optarg);
      break;
    case 't':
      debug_print_time_level = atoi(optarg);
      break;
    case 'p':
      target_pid = atoi(optarg);
      break;
    case 's':
      single_line = 1;
      break;
    case 'o':
      stack_out = optarg;
      break;
    case 'f':
      frame_check = 1;
      break;
    case 'm':
      trace_multiple_procs = atoi(optarg);
      break;
    case 'v':
      version_exit();
      break;
    case 'w':
      flush_log = atoi(optarg);
      break;
    case 'k':
      timeout_seconds = atoi(optarg);
      break;
    case 'l':
      lock_all = true;
      break;
    default:
      usage_exit();
      break;
    }
  }
  if (!target_pid)
    usage_exit();
}

/* Sending SIGCONT if target pid is stopped. Since signal is sent in async,
 * we may retry a few times to verify if the target is really started. */
int cont_process_if(int pid)
{
  int retry = 10;
  bool is_stopped = false;
  while ((is_stopped = is_pid_stopped(pid)) && retry-- > 0) {
    DBG(1, "pid %d is stopped. Sending SIGCONT.. (remaining %d times)",
	target_pid, retry);
    int rc = kill(pid, SIGCONT);
    if (rc == ESRCH)
      return 0;
    sleep(2);
  }
  if (is_stopped) {
    DBG(1, "Failed to stop pid %d", pid);
    return 1;
  }
  return 0;
}

/* Checking target process status and sending SIGCONT if needed.
 * If child process (quickstack core logic) is
 * not aborted and target_pid (main pid) is running, we don't check
 * other processes. Otherwise we check all pids (including all LWPs of
 * the target process). */
int cont_all_process(int main_pid, const vector < int >&pids, bool aborted)
{
  int status = 0;
  status = cont_process_if(main_pid);
  if (status <= 0 && !aborted)
    return status;
  DBG(1, "Needs cleanup. Sending SIGCONT to all processes if needed..")
      for (size_t i = 0; i < pids.size(); ++i) {
    int rc = cont_process_if(pids[i]);
    if (rc)
      status = rc;
  }
  if (!status)
    DBG(1, "done.");
  return status;
}


int main(int argc, char **argv)
{
  vector < int >pids;
  if (argc <= 1) {
    usage_exit();
  }
  struct timeval t_begin;
  struct timeval t_current;
  gettimeofday(&t_begin, 0);
  get_options(argc, argv);
  get_pids(target_pid, pids);
  _attach_started = (int *) mmap(0, PAGE_SIZE,
				 PROT_READ | PROT_WRITE,
				 MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  pid_t quickstack_core_pid = fork();
  if (quickstack_core_pid < 0) {
    DBG(1, "Failed to fork quickstack process.. Exit");
    exit(1);
  } else if (quickstack_core_pid == 0) {
    /* quickstack core process */
    init_signals();
    dump_stack(pids);
    exit(0);
  }

  ignore_signals();
  int exit_code = 0;
  char *args = argv[0];
  sprintf(args, "quickstack_watchdog");
  int status;
  bool cleanup_needed = false;
  pid_t exited_pid;
  do {
    exited_pid = waitpid(quickstack_core_pid, &status, WNOHANG);
    if (exited_pid == -1) {
      if (errno == EINTR) {
	continue;
      }
      DBG(1, "Got error on waitpid: %d", exited_pid);
    } else if (exited_pid == 0) {
      /* quickstack is running */
      sleep(1);
      gettimeofday(&t_current, 0);
      if (t_current.tv_sec >= t_begin.tv_sec + timeout_seconds) {
	DBG(1, "Timeout %d seconds reached. Killing quickstack..",
	    timeout_seconds);
	kill(quickstack_core_pid, SIGKILL);
	sleep(1);
      }
    } else {
      /* quickstack ended */
      break;
    }
  }
  while (exited_pid == 0);

  exit_code = WEXITSTATUS(status);
  if (exit_code) {
    DBG(1, "Got rc %d", WEXITSTATUS(status));
    cleanup_needed = true;
  }

  if (WIFSIGNALED(status)) {
    DBG(1, "Killed by signal %d", WTERMSIG(status));
    cleanup_needed = true;
    sleep(5);
  }
  if (*_attach_started) {
    int stop_status = cont_all_process(target_pid, pids, cleanup_needed);
    if (stop_status) {
      DBG(1, "FATAL: SIGCONT target process failed."
	  " Target process remains state T.");
      exit(1);
    }
  }
  exit(exit_code);
}
