# GNU Arm Embedded Toolchain for arm64 macOS
## Overview
Do you?
* Cross compile ARM microcontroller code using the **GNU Arm Embedded Toolchain**?
* Have one of those new **ARM based Apple Macintosh** computers?
* Want to run **arm64 native** versions of the cross compiling tools on that new Mac
  instead of using Rosetta to run the Intel versions under emulation?

If the answer to those 3 questions is yes, then this is the repository for you.
It contains arm64 arm-none-eabi-* binaries that can be used to replace the Intel
binaries that ship in the official GNU Arm Embedded Toolchain package.


## GNU Arm Embedded Toolchain Version 9-2020-q2-update
This repository currently supports the **9-2020-q2-update** of the GNU toolchain.

Hopefully future versions of the toolchain will contain aarch64-apple-darwin 
support from the 
[official download site](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm)
and this repository can be retired.


## Install
* Download this repository from GitHub as either 
  [an archive](https://github.com/adamgreen/arm-none-eabi-for-arm64-apple-darwin/archive/master.zip) 
  or by using ```git clone git@github.com:adamgreen/arm-none-eabi-for-arm64-apple-darwin.git```
* Run the **gnu_install** script found in the root of this repository to create a
  gcc-arm-none-eabi/ folder within the root of this repository. This folder will
  contain a newly downloaded version of the GNU Arm Embedded Toolchain where the 
  binaries have been replaced with native arm64 ones from this repository.
* The **gcc-arm-none-eabi/bin** folder now found in this repository can be used to
  build code for arm microcontrollers using a native arm64 cross compiler.

### Important Note
* macOS may fail to execute gnu_install by simply clicking on it in the Finder.
  Instead right click on gnu_install in the Finder, select the Open option, and 
  then click the Open button in the resulting security warning dialog.

If you don't want to run a random script from the Internet on your computer, you
can download the Intel based
[GNU Arm Embedded Toolchain](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm)
yourself and then manually replace the x86 binaries with the arm64 binaries found 
in the root of this repository.

## Patches Applied
This section provides an overview of the patches/hacks I made to the
[GNU Arm Embedded Toolchain source code](https://developer.arm.com/-/media/Files/downloads/gnu-rm/9-2020q2/gcc-arm-none-eabi-9-2020-q2-update-src.tar.bz2?revision=e2232c7c-4893-46b6-b791-356bdc29fd7f&la=en&hash=8E864863FA6E16582633DEABE590A7C010C8F750)
to produce these binaries. It should be noted that I didn't only make patches
needed to get the code compiling for arm64 but also to:
* Just get it building on my MacBook Air with only XCode installed.
* Improve GDB functionality for macOS and Cortex-M stack unwinding.

---
```diff
diff --git a/build-common.sh b/build-common.sh
index c62f3cf8a4..c42df7fe31 100755
--- a/build-common.sh
+++ b/build-common.sh
@@ -312,12 +312,12 @@ if [ "x$uname_string" == "xlinux" ] ; then
     PACKAGE_NAME_SUFFIX="${host_arch}-linux"
     WGET="wget -q"
 elif [ "x$uname_string" == "xdarwin" ] ; then
-    BUILD=x86_64-apple-darwin10
-    HOST_NATIVE=x86_64-apple-darwin10
+    BUILD=aarch64-apple-darwin20.1.0
+    HOST_NATIVE=aarch64-apple-darwin20.1.0
     READLINK=greadlink
     # Disable parallel build for mac as we will randomly run into "Permission denied" issue.
-    #JOBS=`sysctl -n hw.ncpu`
-    JOBS=1
+    JOBS=`sysctl -n hw.ncpu`
+    #JOBS=1
     GCC_CONFIG_OPTS_LCPP="--with-host-libstdcxx=-static-libgcc -Wl,-lstdc++ -lm"
     MD5="md5 -r"
     PACKAGE_NAME_SUFFIX=mac-$(sw_vers -productVersion)
@@ -337,9 +337,9 @@ fi
 
 SCRIPT=$(basename $0)
 
-RELEASEDATE=$(date +%Y%m%d)
-release_year=$(date +%Y)
-release_month=$(date +%m)
+RELEASEDATE=20200630
+release_year=2020
+release_month=06
 case $release_month in
     01|02|03)
         RELEASEVER=${release_year}-q1-update
```
---
I updated build-common.sh to switch the host environment from 
**x86_64-apple-darwin10** to **aarch64-apple-darwin20.1.0**  This change is
obviously part of getting it to produce 64-bit ARM binaries.

I also updated this script to:
* Enable multi-threaded build to take advantage of the 8 cores on my ARM based 
  MacBook Air. I perform a minimal build so maybe that is why I don't hit the race
  conditions that forced the original authors to hardcode the build to be single
  threaded.
* I hardcoded the date to the release date of the q2-update instead of the current 
  build date so that it would get the version name correct.


---
```diff
diff --git a/build-prerequisites.sh b/build-prerequisites.sh
index e60b862a9c..7a5cbbf01a 100755
--- a/build-prerequisites.sh
+++ b/build-prerequisites.sh
@@ -211,7 +211,7 @@ if [ "x$skip_native_build" != "xyes" ] ; then
     rm -rf $BUILDDIR_NATIVE/libelf && mkdir -p $BUILDDIR_NATIVE/libelf
     pushd $BUILDDIR_NATIVE/libelf
 
-    $SRCDIR/$LIBELF/configure --build=$BUILD \
+    CFLAGS="-Wno-implicit-function-declaration" $SRCDIR/$LIBELF/configure --build=$BUILD \
         --host=$HOST_NATIVE \
         --target=$TARGET \
         --prefix=$BUILDDIR_NATIVE/host-libs/usr \
```
---
The above update to build-prerequisites.sh was done to just get it to compile in
my build environment. Without this change, the build would fail when Clang noticed
Standard C functions like ```exit()``` being called without the correct header being
included.


---
```diff
diff --git a/build-toolchain.sh b/build-toolchain.sh
index 3aa9f7109f..cdaf707496 100755
--- a/build-toolchain.sh
+++ b/build-toolchain.sh
@@ -527,7 +527,7 @@ if [ "x$skip_native_build" != "xyes" ] ; then
         rm -rf $BUILDDIR_NATIVE/gdb && mkdir -p $BUILDDIR_NATIVE/gdb
         pushd $BUILDDIR_NATIVE/gdb
         saveenv
-        saveenvvar CFLAGS "$ENV_CFLAGS"
+        saveenvvar CFLAGS "$ENV_CFLAGS -Wno-implicit-function-declaration"
         saveenvvar CPPFLAGS "$ENV_CPPFLAGS"
         saveenvvar LDFLAGS "$ENV_LDFLAGS"
 
@@ -594,6 +594,11 @@ if [ "x$skip_native_build" != "xyes" ] ; then
         popd
     fi
 
+# I don't want to strip symbols from libraries, create package or build mingw version so stop here.
+if [ "0" == "0" ] ; then
+  exit 0
+fi
+
     echo Task [III-8] /$HOST_NATIVE/pretidy/ | tee -a "$BUILDDIR_NATIVE/.stage"
     rm -rf $INSTALLDIR_NATIVE/lib/libiberty.a
     find $INSTALLDIR_NATIVE -name '*.la' -exec rm '{}' ';'
```
---
The above updates contain a fix similar to what I made in build-prerequisites.sh
It also contains an early out that I have added since I want to guarantee that the
script never strips the symbols from the binaries or attempts to build mingw
binaries, no matter what I provide in the ```--skip_steps``` command line parameter.


---
```diff
diff --git a/src/gcc/gcc/config.host b/src/gcc/gcc/config.host
index 816a0f06cb..d2bed94100 100644
--- a/src/gcc/gcc/config.host
+++ b/src/gcc/gcc/config.host
@@ -255,6 +255,10 @@ case ${host} in
     out_host_hook_obj="${out_host_hook_obj} host-i386-darwin.o"
     host_xmake_file="${host_xmake_file} i386/x-darwin"
     ;;
+  aarch64-*-darwin*)
+    out_host_hook_obj="${out_host_hook_obj} host-aarch64-darwin.o"
+    host_xmake_file="${host_xmake_file} aarch64/x-darwin"
+    ;;
   powerpc-*-darwin*)
     out_host_hook_obj="${out_host_hook_obj} host-ppc-darwin.o"
     host_xmake_file="${host_xmake_file} rs6000/x-darwin"
diff --git a/src/gcc/gcc/config/aarch64/x-darwin b/src/gcc/gcc/config/aarch64/x-darwin
new file mode 100644
index 0000000000..6d788d5e89
--- /dev/null
+++ b/src/gcc/gcc/config/aarch64/x-darwin
@@ -0,0 +1,3 @@
+host-aarch64-darwin.o : $(srcdir)/config/aarch64/host-aarch64-darwin.c
+	$(COMPILE) $<
+	$(POSTCOMPILE)
```
---
The above changes were required to let the configure script for building GCC
know about the arm64 (aarch64) variant for the Darwin kernel (macOS/iOS).
It will actually cause the following new source file (which was copied from the
existing x86_64 folder) to be built.


---
```diff
diff --git a/src/gcc/gcc/config/aarch64/host-aarch64-darwin.c b/src/gcc/gcc/config/aarch64/host-aarch64-darwin.c
new file mode 100644
index 0000000000..cedcfd389e
--- /dev/null
+++ b/src/gcc/gcc/config/aarch64/host-aarch64-darwin.c
@@ -0,0 +1,32 @@
+/* aarch64-darwin host-specific hook definitions.
+   Copyright (C) 2003-2019 Free Software Foundation, Inc.
+
+This file is part of GCC.
+
+GCC is free software; you can redistribute it and/or modify it under
+the terms of the GNU General Public License as published by the Free
+Software Foundation; either version 3, or (at your option) any later
+version.
+
+GCC is distributed in the hope that it will be useful, but WITHOUT ANY
+WARRANTY; without even the implied warranty of MERCHANTABILITY or
+FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
+for more details.
+
+You should have received a copy of the GNU General Public License
+along with GCC; see the file COPYING3.  If not see
+<http://www.gnu.org/licenses/>.  */
+
+#define IN_TARGET_CODE 1
+
+#include "config.h"
+#include "system.h"
+#include "coretypes.h"
+#include "hosthooks.h"
+#include "hosthooks-def.h"
+#include "config/host-darwin.h"
+
+/* Darwin doesn't do anything special for aarch64 hosts; this file exists just
+   to include config/host-darwin.h.  */
+
+const struct host_hooks host_hooks = HOST_HOOKS_INITIALIZER;
```
---
The following update to host-darwin.c was made to change the alignment of pch_address_space
to 16k, the new larger page size used on arm64 versions of Darwin. Previously Darwin
only ever used a page size of 4k.

---
```diff
diff --git a/src/gcc/gcc/config/host-darwin.c b/src/gcc/gcc/config/host-darwin.c
index 49d3af77a9..557363de09 100644
--- a/src/gcc/gcc/config/host-darwin.c
+++ b/src/gcc/gcc/config/host-darwin.c
@@ -24,7 +24,7 @@
 #include "config/host-darwin.h"
 
 /* Yes, this is really supposed to work.  */
-static char pch_address_space[1024*1024*1024] __attribute__((aligned (4096)));
+static char pch_address_space[1024*1024*1024] __attribute__((aligned (16384)));
 
 /* Return the address of the PCH address space, if the PCH will fit in it.  */
```
---
The following updates to the GMP library were made to allow the ARM64 assembly
language sources to be assembled successfully when targeted for Darwin based
Mach-O instead of Linux COFF output:

---
```diff
diff --git a/src/gmp-6.1.0/mpn/arm64/gcd_1.asm b/src/gmp-6.1.0/mpn/arm64/gcd_1.asm
index bc03d80ddf..9c267cb073 100644
--- a/src/gmp-6.1.0/mpn/arm64/gcd_1.asm
+++ b/src/gmp-6.1.0/mpn/arm64/gcd_1.asm
@@ -82,13 +82,13 @@ C Both U and V are single limbs, reduce with bmod if u0 >> v0.
 	b.hi	L(red1)
 
 L(bmod):mov	x3, #0			C carry argument
-	bl	mpn_modexact_1c_odd
+	bl	GSYM_PREFIX`'mpn_modexact_1c_odd
 	b	L(red0)
 
 L(nby1):cmp	n, #BMOD_1_TO_MOD_1_THRESHOLD
 	b.lo	L(bmod)
 
-	bl	mpn_mod_1
+	bl	GSYM_PREFIX`'mpn_mod_1
 
 L(red0):mov	x3, x0
 L(red1):cmp	x3, #0
diff --git a/src/gmp-6.1.0/mpn/arm64/invert_limb.asm b/src/gmp-6.1.0/mpn/arm64/invert_limb.asm
index a94b0e9611..bb876d97c5 100644
--- a/src/gmp-6.1.0/mpn/arm64/invert_limb.asm
+++ b/src/gmp-6.1.0/mpn/arm64/invert_limb.asm
@@ -41,9 +41,9 @@ C Compiler generated, mildly edited.  Could surely be further optimised.
 ASM_START()
 PROLOGUE(mpn_invert_limb)
 	lsr	x2, x0, #54
-	adrp	x1, approx_tab
+	adrp	x1, approx_tab@PAGE
 	and	x2, x2, #0x1fe
-	add	x1, x1, :lo12:approx_tab
+	add	x1, x1, approx_tab@PAGEOFF
 	ldrh	w3, [x1,x2]
 	lsr	x4, x0, #24
 	add	x4, x4, #1
```
---
The following changes were made in arm-tdep.c to improve GDB's stack stack unwinding
when it encounters an exception frame on a Cortex-M device. If you have ever seen a
callstack which stops at the point an exception handler starts to run and you can't
see the code which the exception handler interrupted then you will know what this
update was made to correct. It handles the use of PSP vs MSP for the interrupted 
code and the additional exception stack frame that can be used when the FPU is 
enabled on a Cortex-M device.

---
```diff
diff --git a/src/gdb/gdb/arm-tdep.c b/src/gdb/gdb/arm-tdep.c
index c0c20c55b9..5c8022b96f 100644
--- a/src/gdb/gdb/arm-tdep.c
+++ b/src/gdb/gdb/arm-tdep.c
@@ -2938,12 +2938,32 @@ arm_m_exception_cache (struct frame_info *this_frame)
   struct arm_prologue_cache *cache;
   CORE_ADDR unwound_sp;
   LONGEST xpsr;
+  CORE_ADDR exc_return;
+  int was_psp_used;
+  int is_extended_frame;
+  int stack_regnum;
 
   cache = FRAME_OBSTACK_ZALLOC (struct arm_prologue_cache);
   cache->saved_regs = trad_frame_alloc_saved_regs (this_frame);
 
-  unwound_sp = get_frame_register_unsigned (this_frame,
-					    ARM_SP_REGNUM);
+  /* Determine which stack pointer (PSP or MSP) was used to stack
+     faulting routines registers. */
+  exc_return = get_frame_register_unsigned (this_frame, ARM_LR_REGNUM);
+  was_psp_used = (exc_return & 0xf) == 0xd;
+  is_extended_frame = (exc_return & (1 << 4)) == 0;
+  stack_regnum = ARM_SP_REGNUM;
+  if (was_psp_used)
+    {
+      int psp = user_reg_map_name_to_regnum (gdbarch, "psp", -1);
+      if (psp == -1)
+	{
+	  warning (_("Interrupted code uses PSP but your target doesn't "
+		     "expose that stack pointer."));
+	}
+      else
+	stack_regnum = psp;
+    }
+  unwound_sp = get_frame_register_unsigned (this_frame, stack_regnum);
 
   /* The hardware saves eight 32-bit words, comprising xPSR,
      ReturnAddress, LR (R14), R12, R3, R2, R1, R0.  See details in
@@ -2958,10 +2978,44 @@ arm_m_exception_cache (struct frame_info *this_frame)
   cache->saved_regs[15].addr = unwound_sp + 24;
   cache->saved_regs[ARM_PS_REGNUM].addr = unwound_sp + 28;
 
+  if (is_extended_frame)
+    {
+      LONGEST fpccr;
+
+      /* Can skip extracting floating pointer registers if the lazy stack
+         is still active. */
+      if (safe_read_memory_integer (0xE000EF34, 4, byte_order, &fpccr)
+	  && (fpccr & 1) == 0)
+	{
+	  int s0_offset = user_reg_map_name_to_regnum (gdbarch, "s0", -1);
+	  int fpscr_offset = user_reg_map_name_to_regnum (gdbarch, "fpscr", -1);;
+
+	  if (s0_offset == -1 || fpscr_offset == -1)
+	    {
+	      warning (_("Interrupted code uses FPU but your target doesn't "
+			 "expose the floating pointer registers."));
+	    }
+	  else
+	    {
+	      int i;
+	      int fpu_reg_offset = unwound_sp + 0x20;
+
+	      for (i = 0; i < 16; ++i, fpu_reg_offset += 4)
+		cache->saved_regs[s0_offset + i].addr = fpu_reg_offset;
+	      cache->saved_regs[fpscr_offset].addr = unwound_sp + 0x60;
+	    }
+	}
+      cache->prev_sp = unwound_sp + 0x68;
+    }
+  else
+    {
+      cache->prev_sp = unwound_sp + 0x20;
+    }
+
+
   /* If bit 9 of the saved xPSR is set, then there is a four-byte
      aligner between the top of the 32-byte stack frame and the
      previous context's stack pointer.  */
-  cache->prev_sp = unwound_sp + 32;
   if (safe_read_memory_integer (unwound_sp + 28, 4, byte_order, &xpsr)
       && (xpsr & (1 << 9)) != 0)
     cache->prev_sp += 4;
```
---
The following updates were made in ser-unix.c to not use a blocking open on the
serial port when using a UART based remote stub. The blocking open can cause GDB to
hang if the serial device (typically some kind of USB based CDC device) doesn't
properly set the carrier detect signal as expected by macOS.

---
```diff
diff --git a/src/gdb/gdb/ser-unix.c b/src/gdb/gdb/ser-unix.c
index 3492619f2d..070c568e3c 100644
--- a/src/gdb/gdb/ser-unix.c
+++ b/src/gdb/gdb/ser-unix.c
@@ -75,7 +75,7 @@ static int hardwire_setstopbits (struct serial *, int);
 static int
 hardwire_open (struct serial *scb, const char *name)
 {
-  scb->fd = gdb_open_cloexec (name, O_RDWR, 0);
+  scb->fd = gdb_open_cloexec (name, O_RDWR | O_NONBLOCK, 0);
   if (scb->fd < 0)
     return -1;
 
@@ -96,6 +96,9 @@ set_tty_state (struct serial *scb, struct hardwire_ttystate *state)
 {
   if (tcsetattr (scb->fd, TCSANOW, &state->termios) < 0)
     return -1;
+  
+  /* Give USB based serial port one frame to handle baud request. */
+  usleep(2000);
 
   return 0;
 }
@@ -341,7 +344,7 @@ rate_to_code (int rate)
 
   for (i = 0; baudtab[i].rate != -1; i++)
     {
-      /* test for perfect macth.  */
+      /* test for perfect match.  */
       if (rate == baudtab[i].rate)
         return baudtab[i].code;
       else
```
---

You can find all of the above patches in **arm64.diff**
