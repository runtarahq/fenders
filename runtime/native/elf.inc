// An argument `fd:N` names a descriptor the launcher opened and passed down
// (a run that dropped to its own uid cannot reopen the files by path);
// anything else is a path. -1 for a path.
static int inherited_file(const char *argument) {
    if (strncmp(argument, "fd:", 3)) return -1;
    char *end; long fd = strtol(argument + 3, &end, 10);
    if (!argument[3] || *end || fd < 3 || fd > 1023 || fcntl((int)fd, F_GETFD) < 0) { fprintf(DIAGNOSTICS,"invalid inherited file: %s\n", argument); exit(2); }
    return (int)fd;
}
static uint8_t *read_file(const char *path, size_t *size) {
    int fd = inherited_file(path); if (fd < 0) fd = open(path, O_RDONLY | O_CLOEXEC); CHECK(fd);
    struct stat st; CHECK(fstat(fd, &st));
    if (st.st_size <= 0 || st.st_size > 16 * 1024 * 1024) { fprintf(DIAGNOSTICS,"invalid file size\n"); exit(1); }
    *size = st.st_size;
    uint8_t *data = malloc(*size); if (!data) fail("malloc");
    size_t n = 0; while (n < *size) { ssize_t r = pread(fd, data + n, *size - n, (off_t)n); if (r <= 0) fail("read"); n += r; }
    close(fd); return data;
}
static void permissions(uint64_t addr, size_t size, uint64_t flags) {
    uint64_t *pte = (void *)(mem + page_tables);
    for (uint64_t p = addr & ~4095ull; p < addr + size; p += 4096) pte[p/4096] = p | flags;
}
// Maps a loadable segment's file pages copy-on-write at its guest address,
// so its pages come from the page cache that every VM shares and only pages
// the guest writes are copied. The bytes of its first and last pages that lie
// outside the segment are zeroed, as a copy into zeroed memory left them.
// Returns 0 where it cannot (offset and address not congruent, or a page
// shared with the previous segment), and the caller copies instead.
static int map_segment(int fd, const Elf64_Phdr *p, uint64_t mapped_end) {
    uint64_t start = p->p_vaddr & ~(uint64_t)(PAGE - 1), lead = p->p_vaddr - start;
    if (!p->p_filesz || (p->p_offset & (PAGE - 1)) != lead || start < mapped_end) return 0;
    uint64_t end = (p->p_vaddr + p->p_filesz + PAGE - 1) & ~(uint64_t)(PAGE - 1);
    void *at = mmap(mem + start, end - start, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, fd, (off_t)(p->p_offset - lead));
    if (at == MAP_FAILED) fail("mmap segment");
    if (lead) memset(mem + start, 0, lead);
    uint64_t tail = p->p_vaddr + p->p_filesz;
    if (end > tail) memset(mem + tail, 0, end - tail);
    return 1;
}
static uint64_t load_guest(const char *path) {
    int fd = inherited_file(path); if (fd < 0) fd = open(path, O_RDONLY | O_CLOEXEC); CHECK(fd);
    struct stat st; CHECK(fstat(fd, &st));
    if (st.st_size <= 0 || st.st_size > 16 * 1024 * 1024) { fprintf(DIAGNOSTICS,"invalid file size\n"); exit(1); }
    size_t size = st.st_size;
    uint8_t *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0); if (data == MAP_FAILED) fail("mmap guest");
    Elf64_Ehdr *e = (void *)data;
    uint64_t mapped_end = 0;
    if (size < sizeof(*e) || memcmp(e->e_ident, ELFMAG, SELFMAG) || e->e_ident[EI_CLASS] != ELFCLASS64 || e->e_machine != EM_X86_64 || e->e_type != ET_EXEC || e->e_phentsize != sizeof(Elf64_Phdr) || e->e_phoff > size || e->e_phnum > (size - e->e_phoff)/sizeof(Elf64_Phdr)) {
        fprintf(DIAGNOSTICS,"invalid guest ELF\n"); exit(1);
    }
    int entry_ok = 0;
    for (unsigned i = 0; i < e->e_phnum; ++i) {
        Elf64_Phdr *p = (void *)(data + e->e_phoff + i * sizeof(*p));
        if (p->p_type != PT_LOAD) continue;
        if (p->p_vaddr < 0x100000 || p->p_vaddr >= page_tables || p->p_memsz > page_tables - p->p_vaddr || p->p_filesz > p->p_memsz || p->p_offset > size || p->p_filesz > size - p->p_offset || (p->p_flags & (PF_W|PF_X)) == (PF_W|PF_X)) { fprintf(DIAGNOSTICS,"invalid ELF segment\n"); exit(1); }
        if (!map_segment(fd, p, mapped_end)) memcpy(mem + p->p_vaddr, data + p->p_offset, p->p_filesz);
        uint64_t file_end = (p->p_vaddr + p->p_filesz + PAGE - 1) & ~(uint64_t)(PAGE - 1);
        if (file_end > mapped_end) mapped_end = file_end;
        reserve_pages(p->p_vaddr,p->p_memsz);
        if(p->p_vaddr+p->p_memsz>image_end) image_end=p->p_vaddr+p->p_memsz;
        permissions(p->p_vaddr, p->p_memsz, 1 | ((p->p_flags & PF_W) ? 2 : 0) | ((p->p_flags & PF_X) ? 0 : NX));
        if ((p->p_flags & PF_X) && e->e_entry >= p->p_vaddr && e->e_entry - p->p_vaddr < p->p_memsz) entry_ok = 1;
    }
    if (!entry_ok) { fprintf(DIAGNOSTICS,"entry outside code\n"); exit(1); }
    elf_phdr=e->e_phoff;elf_phnum=e->e_phnum;
    for(unsigned i=0;i<e->e_phnum;i++) {Elf64_Phdr *p=(void *)(data+e->e_phoff+i*sizeof(*p));if(p->p_type==PT_LOAD && p->p_offset==0) {elf_phdr+=p->p_vaddr;break;}}
    uint64_t entry = e->e_entry; munmap(data, size); close(fd); return entry;
}
