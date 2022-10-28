This is the bug report of the NVIDIA GForce RTX 3060 Laptop GPU

```
____________________________________________

Start of NVIDIA bug report log file.  Please include this file, along
with a detailed description of your problem, when reporting a graphics
driver bug via the NVIDIA Linux forum (see forums.developer.nvidia.com)
or by sending email to 'linux-bugs@nvidia.com'.

nvidia-bug-report.sh Version: 31831145

Date: Thu Oct 27 08:50:11 PM -03 2022
uname: Linux nomade007 6.0.1-arch2-1 #1 SMP PREEMPT_DYNAMIC Thu, 13 Oct 2022 18:58:49 +0000 x86_64 GNU/Linux
command line flags: 

____________________________________________

*** /sys/bus/pci/devices/0000:01:00.0/power/control
*** ls: -rw-r--r-- 1 root root 4096 2022-10-27 20:48:36.350700867 -0300 /sys/bus/pci/devices/0000:01:00.0/power/control
auto

____________________________________________

*** /sys/bus/pci/devices/0000:01:00.0/power/runtime_status
*** ls: -r--r--r-- 1 root root 4096 2022-10-27 20:48:36.350700867 -0300 /sys/bus/pci/devices/0000:01:00.0/power/runtime_status
suspended

____________________________________________

*** /sys/bus/pci/devices/0000:01:00.0/power/runtime_usage does not exist

____________________________________________

*** /sys/bus/pci/devices/0000:01:00.1/power/control
*** ls: -rw-r--r-- 1 root root 4096 2022-10-27 20:48:36.350700867 -0300 /sys/bus/pci/devices/0000:01:00.1/power/control
auto

____________________________________________

*** /sys/bus/pci/devices/0000:01:00.1/power/runtime_status
*** ls: -r--r--r-- 1 root root 4096 2022-10-27 20:48:36.350700867 -0300 /sys/bus/pci/devices/0000:01:00.1/power/runtime_status
suspended

____________________________________________

*** /sys/bus/pci/devices/0000:01:00.1/power/runtime_usage does not exist

____________________________________________

*** /proc/driver/nvidia/./gpus/0000:01:00.0/power
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:48:33.974169298 -0300 /proc/driver/nvidia/./gpus/0000:01:00.0/power
Runtime D3 status:          Enabled (fine-grained)
Video Memory:               Off

GPU Hardware Support:
 Video Memory Self Refresh: Supported
 Video Memory Off:          Supported

Power Limits:
 Default:                   N/A milliwatts
 GPU Boost:                 N/A milliwatts

____________________________________________

*** /etc/issue
*** ls: -rw-r--r-- 1 root root 20 2021-12-06 23:41:28.000000000 -0300 /etc/issue
Arch Linux \r (\l)


____________________________________________

*** /var/log/nvidia-installer.log does not exist

____________________________________________

/sbin/systemctl status nvidia-suspend.service nvidia-hibernate.service nvidia-resume.service nvidia-powerd.service
○ nvidia-suspend.service - NVIDIA system suspend actions
     Loaded: loaded (/usr/lib/systemd/system/nvidia-suspend.service; disabled; preset: disabled)
     Active: inactive (dead)

○ nvidia-hibernate.service - NVIDIA system hibernate actions
     Loaded: loaded (/usr/lib/systemd/system/nvidia-hibernate.service; disabled; preset: disabled)
     Active: inactive (dead)

○ nvidia-resume.service - NVIDIA system resume actions
     Loaded: loaded (/usr/lib/systemd/system/nvidia-resume.service; disabled; preset: disabled)
     Active: inactive (dead)

○ nvidia-powerd.service - nvidia-powerd service
     Loaded: loaded (/usr/lib/systemd/system/nvidia-powerd.service; disabled; preset: disabled)
     Active: inactive (dead)

____________________________________________

journalctl -b -0 _COMM=Xorg

-- No entries --

____________________________________________

journalctl -b -1 _COMM=Xorg

-- No entries --

____________________________________________

journalctl -b -2 _COMM=Xorg

-- No entries --

____________________________________________

journalctl -b -0 _COMM=Xorg.bin

-- No entries --

____________________________________________

journalctl -b -1 _COMM=Xorg.bin

-- No entries --

____________________________________________

journalctl -b -2 _COMM=Xorg.bin

-- No entries --

____________________________________________

journalctl -b -0 _COMM=X

-- No entries --

____________________________________________

journalctl -b -1 _COMM=X

-- No entries --

____________________________________________

journalctl -b -2 _COMM=X

-- No entries --

____________________________________________

journalctl -b -0 _COMM=gdm-x-session

-- No entries --

____________________________________________

journalctl -b -1 _COMM=gdm-x-session

-- No entries --

____________________________________________

journalctl -b -2 _COMM=gdm-x-session

-- No entries --

____________________________________________

/sbin/coredumpctl info COREDUMP_COMM=Xorg COREDUMP_COMM=Xorg.bin COREDUMP_COMM=X
           PID: 853 (Xorg)
           UID: 120 (gdm)
           GID: 120 (gdm)
        Signal: 6 (ABRT)
     Timestamp: Thu 2022-03-10 10:41:55 -03 (7 months 18 days ago)
  Command Line: /usr/lib/Xorg vt1 -displayfd 3 -auth /run/user/120/gdm/Xauthority -nolisten tcp -background none -noreset -keeptty -novtswitch -verbose 3
    Executable: /usr/lib/Xorg
 Control Group: /user.slice/user-120.slice/session-1.scope
          Unit: session-1.scope
         Slice: user-120.slice
       Session: 1
     Owner UID: 120 (gdm)
       Boot ID: f7d0054ea93e49b8b7e3061b6c7c5765
    Machine ID: 2cd8378f24ec4d6fa72a08a226f4a6f8
      Hostname: nomade007
       Storage: /var/lib/systemd/coredump/core.Xorg.120.f7d0054ea93e49b8b7e3061b6c7c5765.853.1646919715000000.zst (missing)
       Message: Process 853 (Xorg) of user 120 dumped core.
                
                Module linux-vdso.so.1 with build-id 233c52c1d27fec7ef70fa5ba700262adfc01106e
                Module libxcb-sync.so.1 with build-id dda14591103b01b1311906053bf1ca9e82ade35c
                Module libxcb-present.so.0 with build-id 68f5465258750e2397b1333b3ffc01ee33caa4e1
                Module libxcb-dri3.so.0 with build-id 9407a2480e09dc5a1dd9d9a0652fa8d32b328c91
                Module libxcb-xfixes.so.0 with build-id a6b197ace5b9b59f913f5969eb419a88d1194f47
                Module libxcb-dri2.so.0 with build-id 2dd6e65129a809dab828a1d26215a3f7a363fcc8
                Module libX11-xcb.so.1 with build-id 0db4f94d8ae31b8dc9a83f825a9171656f1e532c
                Module libEGL_mesa.so.0 with build-id a4c0e92af4f4a171dd0d64b36bb354ae261d8060
                Module libnvidia-egl-gbm.so.1 with build-id e0818354660c8a99ce2f72bda50cf4a2eae7bd7d
                Module libnvidia-eglcore.so.510.54 with build-id 268f01c1ec0dd7f386f7d4adc77e577943432c26
                Module libwayland-client.so.0 with build-id 0a237f2fd096bada4ca381eec5d64474c4078be4
                Module libnvidia-egl-wayland.so.1 with build-id 7026a2a5082aff391d23ed5af4678c543383f2d9
                Module libnvidia-glsi.so.510.54 with build-id 6e562292b666f11bb7f2759532ae2c7efcd0d8b5
                Module libEGL_nvidia.so.0 with build-id e5b0f6f6126cc13ca595af6a7a84ab1c626b9150
                Module libEGL.so.1 with build-id 686c2e4036c01a3a72349ed0dd04f7c434af14ce
                Module libepoxy.so.0 with build-id b6357fc6b748c512f90339433d74502b9d0621dc
                Module libglamoregl.so with build-id 9946c4fe5d58edfa7b116735d3d1f8dd00c9a13a
                Module libgobject-2.0.so.0 with build-id 1ab19051c262a2c995e86ea2b0af7e8ab70798f3
                Module libgudev-1.0.so.0 with build-id a9f734ea9206d637d5aacfbd86298c91cdc1a33a
                Module libwacom.so.9 with build-id 7e303135e132c1d883060092e9b4cc5971a94378
                Module libevdev.so.2 with build-id b62ae69f839f1b6b06ef2c1df19f25ff09b0d824
                Module libmtdev.so.1 with build-id 0cea2a842ae9a0ef02a08477076caab0e5ac5e42
                Module libinput.so.10 with build-id 1303998925dd344a6a55546c2f9ce6b936c97cb7
                Module libinput_drv.so with build-id cf829f2000cbe7c7b226d0bc4c8188ab0fa99b62
                Module libicudata.so.70 with build-id e1dcc2a88cfaafed882d09c90c668af0eed4efed
                Module libicuuc.so.70 with build-id 2e245c2bf12f95fd8ab79b3a4be99524677cbd70
                Module libxml2.so.2 with build-id 34aa03d6fadb52a051964f0e50a977efaea9482e
                Module libncursesw.so.6 with build-id 1f873ddb2c32ab39d0b7d8646d03680ffe99de7c
                Module libedit.so.0 with build-id 4b0babfcad161c2ad0af6e59e2493258db23a331
                Module libstdc++.so.6 with build-id 88ad4eff81a00c684abfe0f863e87434123d8943
                Module libvulkan.so.1 with build-id 40c7a455d37803dbd362377df831a77142acb66b
                Module libdrm_nouveau.so.2 with build-id af8afb2331ac08c52132102ecbdc6076a8eb4c6f
                Module libdrm_amdgpu.so.1 with build-id 8eb3977b830f3012d9ead7b4def5f4d2f38ec688
                Module libelf.so.1 with build-id 4cf96cb4785e1ca233693ae17fa0d62971ee09c2
                Module libdrm_radeon.so.1 with build-id 43e0aecc70c4ce905ba35c948e1c9a5d999b14c0
                Module libsensors.so.5 with build-id dc8b2c1c0d8525411aca188ea3cc3fb86d381d30
                Module libLLVM-13.so with build-id 62bb83aeee3a955305312248a401be2cf62a0ea8
                Module libglapi.so.0 with build-id 7aa51925ea129481550b50f3ded60c755e169faa
                Module swrast_dri.so with build-id c43e3cc6cde38c8c92a9612fcdb368153bc65720
                Module libnvidia-glcore.so.510.54 with build-id 7576be7cecae485aa6f8120c1f040126301938e7
                Module libnvidia-tls.so.510.54 with build-id 1f7f903b99300700f138d986877210c4e12316f7
                Module libglxserver_nvidia.so with build-id 936ef2654b2b83076185d2f83843f769f4f44a28
                Module libshadow.so with build-id 62fdf570bdccbb9e8a74992beb3d4b2c81437f42
                Module libwfb.so with build-id 4d699ae0f9d586164b9aaba02a88ee2d21db382d
                Module libfbdevhw.so with build-id 3f5ed63456dc94681fb387e5f22a0631acdbc24f
                Module fbdev_drv.so with build-id b6099b37e2e289df21b4407d2b07fcb90b9637d5
                Module libffi.so.8 with build-id f90d8b734f6de9b25faedb8cbfab7054dafc0a42
                Module libexpat.so.1 with build-id 63a4ee083a938cbb472c2c4d32e1050474c94382
                Module libwayland-server.so.0 with build-id 645526447334b85a6f4bf5a8b37737b27696365f
                Module libgbm.so.1 with build-id b1e71b2fbf996e9e3f95978d5fb1c35257fc739d
                Module modesetting_drv.so with build-id b2f9309167a72c1acd0f3edd41f27cc7134205cf
                Module nvidia_drv.so with build-id 86958c7412f56f66bc515077ed6ee91d2130ea22
                Module libxcb.so.1 with build-id 0d1ef11740a5daad2ee331e812a51aa6574af222
                Module libX11.so.6 with build-id 5ba5798d193c0065014b8c6252a0678671c8d478
                Module libGLX.so.0 with build-id 2a08836c6e6126ce9ff4496b6aacaf29ae9b4e7b
                Module libGLdispatch.so.0 with build-id 501765b3a78d668860fa54229b18107473aeda4c
                Module libGL.so.1 with build-id 912ac4f37a9fa2d5abcf7a9088c9983cfe46f12a
                Module libglx.so with build-id 8f3a3102dfa2c3af12bb5459e847ca16f0aa0b93
                Module libpcre.so.1 with build-id 845483dd0acba86de9f0313102bebbaf3ce52767
                Module libbrotlicommon.so.1 with build-id a4ba3f4b4571c8272343b621da812a6e24a202a7
                Module libglib-2.0.so.0 with build-id 0fcc81d3dfd68bddbf63423156549fc66939e8ca
                Module libgraphite2.so.3 with build-id 47761dc11e553f519cde97ed9ee985be12ccdae2
                Module libresolv.so.2 with build-id 46ffdf3d477a170314060c26927470d7399bc900
                Module libkeyutils.so.1 with build-id ac405ddd17be10ce538da3211415ee50c8f8df79
                Module libdl.so.2 with build-id bb9bd2657bfba9f60bd34d2050cc63a7eb024bc4
                Module libkrb5support.so.0 with build-id adf65240a4d2aba772d7a0772b4d015469934113
                Module libcom_err.so.2 with build-id 358b783c9b3d12ba8248519ea2e7f3da4c4e0297
                Module libk5crypto.so.3 with build-id eb8220b8f36675aac769450be4cb6bb7f97ec38a
                Module libkrb5.so.3 with build-id 72d26767c5cb1097db75a5f5bff88860233c902b
                Module libgpg-error.so.0 with build-id 82524ee3d1c4c2244d7cfdcc1e6eea5f9855f6c6
                Module libbrotlidec.so.1 with build-id 45defc036e918e0140a72f1fbce6e7692d38241d
                Module libharfbuzz.so.0 with build-id 89c433487528544bfa68f5336fb35b15ba988f82
                Module libpng16.so.16 with build-id 2dc0bce07f199bf983c07a05fb95a6f4af83a9b3
                Module libbz2.so.1.0 with build-id 919597c477c9b2cb9cdbb7745ed6494ac0e6da60
                Module libgssapi_krb5.so.2 with build-id e6e098ad51ce7bdd3dbe902d7b0f69a90f8a9e08
                Module libpthread.so.0 with build-id 7fa8b52fae071a370ba4ca32bf9490a30aff31c4
                Module libgcc_s.so.1 with build-id 5d817452a709ca3a213341555ddcf446ecee37fa
                Module libgcrypt.so.20 with build-id db45f5d5e0f7af1e77324fea1885f974619ad268
                Module libcap.so.2 with build-id eb6dae97527fc89dbb0d5bb581a15acd02ae9f56
                Module liblz4.so.1 with build-id e63600ab23b2f6997f42fac2fa56e1f02ce159a1
                Module libzstd.so.1 with build-id 72f3511cba7db578f6a2647925f35664da6c838b
                Module liblzma.so.5 with build-id 8b615460aa230708c5183f16bede67aa0437d95e
                Module librt.so.1 with build-id 4761858b348db8303e872e515aa8d56c046c921c
                Module libfreetype.so.6 with build-id 26c5f833068ff72660d1975cbc2074c3eb47fad8
                Module libfontenc.so.1 with build-id 5a11f1fb8c3f2714be9eb6697318f20e301e1d2f
                Module libz.so.1 with build-id 0c1459c56513efd5d53eb3868290e9afee6a6a26
                Module ld-linux-x86-64.so.2 with build-id c09c6f50f6bcec73c64a0b4be77eadb8f7202410
                Module libc.so.6 with build-id 85766e9d8458b16e9c7ce6e07c712c02b8471dbc
                Module libxcvt.so.0 with build-id 30bad674c8227152bb709556a3657d0258554309
                Module libtirpc.so.3 with build-id 5bef2adfdee3df283f593b3e2d37b6dac405256a
                Module libdrm.so.2 with build-id 00816f0a71c7e4e388c10db6245dbb9c031732a9
                Module libudev.so.1 with build-id 10425bceda4d2b8dfaa2453dd7e833ea873f88a1
                Module libdbus-1.so.3 with build-id 7f4b16b4b407cbae2d7118d6f99610e29a18a56a
                Module libsystemd.so.0 with build-id a83a62063b8098eda274d25251d619f0503bf011
                Module libxshmfence.so.1 with build-id 8876d9ccf620858795724ca24b9e567585a77cec
                Module libXfont2.so.2 with build-id 154202dd7ddb86f6ae4d3bc762dfd8570b86882a
                Module libXdmcp.so.6 with build-id 8ca0792d23c8b8b4c0864297512349292bea5955
                Module libXau.so.6 with build-id 1c67764663e07bec24d8951e5fd93f4d165979ff
                Module libnettle.so.8 with build-id 9a878e513c02007598fcf1e2e286c2203f13536e
                Module libpciaccess.so.0 with build-id 9dd24e76ebc38465541313b36446ffb4af842c12
                Module libm.so.6 with build-id 596b63a006a4386dcab30912d2b54a7a61827b07
                Module libpixman-1.so.0 with build-id 341f793dcada3a48a306a793d265a517e3f2e7d6
                Module Xorg with build-id 3c6e2db78b3029efb2e8d9069883e807744d2f7e
                Stack trace of thread 853:
                #0  0x00007f6567f9a34c __pthread_kill_implementation (libc.so.6 + 0x8f34c)
                #1  0x00007f6567f4d4b8 raise (libc.so.6 + 0x424b8)
                #2  0x00007f6567f37534 abort (libc.so.6 + 0x2c534)
                #3  0x0000555dc3673a00 OsAbort (Xorg + 0x153a00)
                #4  0x0000555dc3675545 FatalError (Xorg + 0x155545)
                #5  0x0000555dc367af1a n/a (Xorg + 0x15af1a)
                #6  0x00007f6567f4d560 __restore_rt (libc.so.6 + 0x42560)
                #7  0x00007f6567f9a34c __pthread_kill_implementation (libc.so.6 + 0x8f34c)
                #8  0x00007f6567f4d4b8 raise (libc.so.6 + 0x424b8)
                #9  0x00007f6567f37534 abort (libc.so.6 + 0x2c534)
                #10 0x00007f6567f3745c __assert_fail_base.cold (libc.so.6 + 0x2c45c)
                #11 0x00007f6567f46116 __assert_fail (libc.so.6 + 0x3b116)
                #12 0x0000555dc35bbe59 n/a (Xorg + 0x9be59)
                #13 0x00007f5f557ff8cf glamor_init (libglamoregl.so + 0xd8cf)
                #14 0x00007f6568508261 n/a (modesetting_drv.so + 0xf261)
                #15 0x0000555dc359d57e AddGPUScreen (Xorg + 0x7d57e)
                #16 0x0000555dc36af969 n/a (Xorg + 0x18f969)
                #17 0x0000555dc36cecb4 n/a (Xorg + 0x1aecb4)
                #18 0x0000555dc36f3821 n/a (Xorg + 0x1d3821)
                #19 0x0000555dc36f3a13 config_init (Xorg + 0x1d3a13)
                #20 0x0000555dc355c6b5 n/a (Xorg + 0x3c6b5)
                #21 0x00007f6567f38310 __libc_start_call_main (libc.so.6 + 0x2d310)
                #22 0x00007f6567f383c1 __libc_start_main@@GLIBC_2.34 (libc.so.6 + 0x2d3c1)
                #23 0x0000555dc355d795 _start (Xorg + 0x3d795)
                
                Stack trace of thread 881:
                #0  0x00007f6567f9515a __futex_abstimed_wait_common (libc.so.6 + 0x8a15a)
                #1  0x00007f6567f97960 pthread_cond_wait@@GLIBC_2.3.2 (libc.so.6 + 0x8c960)
                #2  0x00007f5f5e5d851c n/a (swrast_dri.so + 0x1db51c)
                #3  0x00007f5f5e5d156c n/a (swrast_dri.so + 0x1d456c)
                #4  0x00007f6567f985c2 start_thread (libc.so.6 + 0x8d5c2)
                #5  0x00007f656801d584 __clone (libc.so.6 + 0x112584)
                
                Stack trace of thread 885:
                #0  0x00007f6567f9515a __futex_abstimed_wait_common (libc.so.6 + 0x8a15a)
                #1  0x00007f6567f97960 pthread_cond_wait@@GLIBC_2.3.2 (libc.so.6 + 0x8c960)
                #2  0x00007f5f5e5d851c n/a (swrast_dri.so + 0x1db51c)
                #3  0x00007f5f5e5d156c n/a (swrast_dri.so + 0x1d456c)
                #4  0x00007f6567f985c2 start_thread (libc.so.6 + 0x8d5c2)
                #5  0x00007f656801d584 __clone (libc.so.6 + 0x112584)
                
                Stack trace of thread 883:
                #0  0x00007f6567f9515a __futex_abstimed_wait_common (libc.so.6 + 0x8a15a)
                #1  0x00007f6567f97960 pthread_cond_wait@@GLIBC_2.3.2 (libc.so.6 + 0x8c960)
                #2  0x00007f5f5e5d851c n/a (swrast_dri.so + 0x1db51c)
                #3  0x00007f5f5e5d156c n/a (swrast_dri.so + 0x1d456c)
                #4  0x00007f6567f985c2 start_thread (libc.so.6 + 0x8d5c2)
                #5  0x00007f656801d584 __clone (libc.so.6 + 0x112584)
                
                Stack trace of thread 874:
                #0  0x00007f6567f9515a __futex_abstimed_wait_common (libc.so.6 + 0x8a15a)
                #1  0x00007f6567f97960 pthread_cond_wait@@GLIBC_2.3.2 (libc.so.6 + 0x8c960)
                #2  0x00007f5f5e5d851c n/a (swrast_dri.so + 0x1db51c)
                #3  0x00007f5f5e5d156c n/a (swrast_dri.so + 0x1d456c)
                #4  0x00007f6567f985c2 start_thread (libc.so.6 + 0x8d5c2)
                #5  0x00007f656801d584 __clone (libc.so.6 + 0x112584)
                
                Stack trace of thread 887:
                #0  0x00007f6567f9515a __futex_abstimed_wait_common (libc.so.6 + 0x8a15a)
                #1  0x00007f6567f97960 pthread_cond_wait@@GLIBC_2.3.2 (libc.so.6 + 0x8c960)
                #2  0x00007f5f5e5d851c n/a (swrast_dri.so + 0x1db51c)
                #3  0x00007f5f5e5d156c n/a (swrast_dri.so + 0x1d456c)
                #4  0x00007f6567f985c2 start_thread (libc.so.6 + 0x8d5c2)
                #5  0x00007f656801d584 __clone (libc.so.6 + 0x112584)
                
                Stack trace of thread 889:
                #0  0x00007f6567f9515a __futex_abstimed_wait_common (libc.so.6 + 0x8a15a)
                #1  0x00007f6567f97960 pthread_cond_wait@@GLIBC_2.3.2 (libc.so.6 + 0x8c960)
                #2  0x00007f5f5e5d851c n/a (swrast_dri.so + 0x1db51c)
                #3  0x00007f5f5e5d156c n/a (swrast_dri.so + 0x1d456c)
                #4  0x00007f6567f985c2 start_thread (libc.so.6 + 0x8d5c2)
                #5  0x00007f656801d584 __clone (libc.so.6 + 0x112584)
                
                Stack trace of thread 886:
                #0  0x00007f6567f9515a __futex_abstimed_wait_common (libc.so.6 + 0x8a15a)
                #1  0x00007f6567f97960 pthread_cond_wait@@GLIBC_2.3.2 (libc.so.6 + 0x8c960)
                #2  0x00007f5f5e5d851c n/a (swrast_dri.so + 0x1db51c)
                #3  0x00007f5f5e5d156c n/a (swrast_dri.so + 0x1d456c)
                #4  0x00007f6567f985c2 start_thread (libc.so.6 + 0x8d5c2)
                #5  0x00007f656801d584 __clone (libc.so.6 + 0x112584)
                
                Stack trace of thread 878:
                #0  0x00007f6567f9515a __futex_abstimed_wait_common (libc.so.6 + 0x8a15a)
                #1  0x00007f6567f97960 pthread_cond_wait@@GLIBC_2.3.2 (libc.so.6 + 0x8c960)
                #2  0x00007f5f5e5d851c n/a (swrast_dri.so + 0x1db51c)
                #3  0x00007f5f5e5d156c n/a (swrast_dri.so + 0x1d456c)
                #4  0x00007f6567f985c2 start_thread (libc.so.6 + 0x8d5c2)
                #5  0x00007f656801d584 __clone (libc.so.6 + 0x112584)
                
                Stack trace of thread 880:
                #0  0x00007f6567f9515a __futex_abstimed_wait_common (libc.so.6 + 0x8a15a)
                #1  0x00007f6567f97960 pthread_cond_wait@@GLIBC_2.3.2 (libc.so.6 + 0x8c960)
                #2  0x00007f5f5e5d851c n/a (swrast_dri.so + 0x1db51c)
                #3  0x00007f5f5e5d156c n/a (swrast_dri.so + 0x1d456c)
                #4  0x00007f6567f985c2 start_thread (libc.so.6 + 0x8d5c2)
                #5  0x00007f656801d584 __clone (libc.so.6 + 0x112584)
                
                Stack trace of thread 876:
                #0  0x00007f6567f9515a __futex_abstimed_wait_common (libc.so.6 + 0x8a15a)
                #1  0x00007f6567f97960 pthread_cond_wait@@GLIBC_2.3.2 (libc.so.6 + 0x8c960)
                #2  0x00007f5f5e5d851c n/a (swrast_dri.so + 0x1db51c)
                #3  0x00007f5f5e5d156c n/a (swrast_dri.so + 0x1d456c)
                #4  0x00007f6567f985c2 start_thread (libc.so.6 + 0x8d5c2)
                #5  0x00007f656801d584 __clone (libc.so.6 + 0x112584)
                
                Stack trace of thread 890:
                #0  0x00007f6567f9515a __futex_abstimed_wait_common (libc.so.6 + 0x8a15a)
                #1  0x00007f6567f97960 pthread_cond_wait@@GLIBC_2.3.2 (libc.so.6 + 0x8c960)
                #2  0x00007f5f5e5d851c n/a (swrast_dri.so + 0x1db51c)
                #3  0x00007f5f5e5d156c n/a (swrast_dri.so + 0x1d456c)
                #4  0x00007f6567f985c2 start_thread (libc.so.6 + 0x8d5c2)
                #5  0x00007f656801d584 __clone (libc.so.6 + 0x112584)
                
                Stack trace of thread 888:
                #0  0x00007f6567f9515a __futex_abstimed_wait_common (libc.so.6 + 0x8a15a)
                #1  0x00007f6567f97960 pthread_cond_wait@@GLIBC_2.3.2 (libc.so.6 + 0x8c960)
                #2  0x00007f5f5e5d851c n/a (swrast_dri.so + 0x1db51c)
                #3  0x00007f5f5e5d156c n/a (swrast_dri.so + 0x1d456c)
                #4  0x00007f6567f985c2 start_thread (libc.so.6 + 0x8d5c2)
                #5  0x00007f656801d584 __clone (libc.so.6 + 0x112584)
                
                Stack trace of thread 872:
                #0  0x00007f6567f9515a __futex_abstimed_wait_common (libc.so.6 + 0x8a15a)
                #1  0x00007f6567f97960 pthread_cond_wait@@GLIBC_2.3.2 (libc.so.6 + 0x8c960)
                #2  0x00007f5f5e5d851c n/a (swrast_dri.so + 0x1db51c)
                #3  0x00007f5f5e5d156c n/a (swrast_dri.so + 0x1d456c)
                #4  0x00007f6567f985c2 start_thread (libc.so.6 + 0x8d5c2)
                #5  0x00007f656801d584 __clone (libc.so.6 + 0x112584)
                
                Stack trace of thread 877:
                #0  0x00007f6567f9515a __futex_abstimed_wait_common (libc.so.6 + 0x8a15a)
                #1  0x00007f6567f97960 pthread_cond_wait@@GLIBC_2.3.2 (libc.so.6 + 0x8c960)
                #2  0x00007f5f5e5d851c n/a (swrast_dri.so + 0x1db51c)
                #3  0x00007f5f5e5d156c n/a (swrast_dri.so + 0x1d456c)
                #4  0x00007f6567f985c2 start_thread (libc.so.6 + 0x8d5c2)
                #5  0x00007f656801d584 __clone (libc.so.6 + 0x112584)
                
                Stack trace of thread 875:
                #0  0x00007f6567f9515a __futex_abstimed_wait_common (libc.so.6 + 0x8a15a)
                #1  0x00007f6567f97960 pthread_cond_wait@@GLIBC_2.3.2 (libc.so.6 + 0x8c960)
                #2  0x00007f5f5e5d851c n/a (swrast_dri.so + 0x1db51c)
                #3  0x00007f5f5e5d156c n/a (swrast_dri.so + 0x1d456c)
                #4  0x00007f6567f985c2 start_thread (libc.so.6 + 0x8d5c2)
                #5  0x00007f656801d584 __clone (libc.so.6 + 0x112584)
                
                Stack trace of thread 873:
                #0  0x00007f6567f9515a __futex_abstimed_wait_common (libc.so.6 + 0x8a15a)
                #1  0x00007f6567f97960 pthread_cond_wait@@GLIBC_2.3.2 (libc.so.6 + 0x8c960)
                #2  0x00007f5f5e5d851c n/a (swrast_dri.so + 0x1db51c)
                #3  0x00007f5f5e5d156c n/a (swrast_dri.so + 0x1d456c)
                #4  0x00007f6567f985c2 start_thread (libc.so.6 + 0x8d5c2)
                #5  0x00007f656801d584 __clone (libc.so.6 + 0x112584)
                
                Stack trace of thread 879:
                #0  0x00007f6567f9515a __futex_abstimed_wait_common (libc.so.6 + 0x8a15a)
                #1  0x00007f6567f97960 pthread_cond_wait@@GLIBC_2.3.2 (libc.so.6 + 0x8c960)
                #2  0x00007f5f5e5d851c n/a (swrast_dri.so + 0x1db51c)
                #3  0x00007f5f5e5d156c n/a (swrast_dri.so + 0x1d456c)
                #4  0x00007f6567f985c2 start_thread (libc.so.6 + 0x8d5c2)
                #5  0x00007f656801d584 __clone (libc.so.6 + 0x112584)
                
                Stack trace of thread 882:
                #0  0x00007f6567f9515a __futex_abstimed_wait_common (libc.so.6 + 0x8a15a)
                #1  0x00007f6567f97960 pthread_cond_wait@@GLIBC_2.3.2 (libc.so.6 + 0x8c960)
                #2  0x00007f5f5e5d851c n/a (swrast_dri.so + 0x1db51c)
                #3  0x00007f5f5e5d156c n/a (swrast_dri.so + 0x1d456c)
                #4  0x00007f6567f985c2 start_thread (libc.so.6 + 0x8d5c2)
                #5  0x00007f656801d584 __clone (libc.so.6 + 0x112584)
                
                Stack trace of thread 884:
                #0  0x00007f6567f9515a __futex_abstimed_wait_common (libc.so.6 + 0x8a15a)
                #1  0x00007f6567f97960 pthread_cond_wait@@GLIBC_2.3.2 (libc.so.6 + 0x8c960)
                #2  0x00007f5f5e5d851c n/a (swrast_dri.so + 0x1db51c)
                #3  0x00007f5f5e5d156c n/a (swrast_dri.so + 0x1d456c)
                #4  0x00007f6567f985c2 start_thread (libc.so.6 + 0x8d5c2)
                #5  0x00007f656801d584 __clone (libc.so.6 + 0x112584)
                ELF object binary architecture: AMD x86-64

____________________________________________

*** /var/log/Xorg.0.log
*** ls: -rw-r--r-- 1 root gdm 68547 2022-10-17 10:36:03.591411285 -0300 /var/log/Xorg.0.log
[     4.737] (--) Log file renamed from "/var/log/Xorg.pid-848.log" to "/var/log/Xorg.0.log"
[     4.737] 
X.Org X Server 1.21.1.4
X Protocol Version 11, Revision 0
[     4.737] Current Operating System: Linux nomade007 6.0.1-arch2-1 #1 SMP PREEMPT_DYNAMIC Thu, 13 Oct 2022 18:58:49 +0000 x86_64
[     4.737] Kernel command line: initrd=\amd-ucode.img initrd=\initramfs-linux.img root=PARTUUID=f407dfcd-5b75-c540-99c7-811fac3135b7 rw
[     4.737]  
[     4.737] Current version of pixman: 0.40.0
[     4.737] 	Before reporting problems, check http://wiki.x.org
	to make sure that you have the latest version.
[     4.737] Markers: (--) probed, (**) from config file, (==) default setting,
	(++) from command line, (!!) notice, (II) informational,
	(WW) warning, (EE) error, (NI) not implemented, (??) unknown.
[     4.737] (==) Log file: "/var/log/Xorg.0.log", Time: Mon Oct 17 07:30:18 2022
[     4.738] (==) Using system config directory "/usr/share/X11/xorg.conf.d"
[     4.739] (==) No Layout section.  Using the first Screen section.
[     4.739] (==) No screen section available. Using defaults.
[     4.739] (**) |-->Screen "Default Screen Section" (0)
[     4.739] (**) |   |-->Monitor "<default monitor>"
[     4.739] (==) No monitor specified for screen "Default Screen Section".
	Using a default monitor configuration.
[     4.739] (==) Automatically adding devices
[     4.739] (==) Automatically enabling devices
[     4.739] (==) Automatically adding GPU devices
[     4.739] (==) Automatically binding GPU devices
[     4.739] (==) Max clients allowed: 256, resource mask: 0x1fffff
[     4.739] (WW) The directory "/usr/share/fonts/misc" does not exist.
[     4.739] 	Entry deleted from font path.
[     4.740] (WW) The directory "/usr/share/fonts/OTF" does not exist.
[     4.740] 	Entry deleted from font path.
[     4.740] (WW) The directory "/usr/share/fonts/Type1" does not exist.
[     4.740] 	Entry deleted from font path.
[     4.740] (==) FontPath set to:
	/usr/share/fonts/TTF,
	/usr/share/fonts/100dpi,
	/usr/share/fonts/75dpi
[     4.740] (==) ModulePath set to "/usr/lib/xorg/modules"
[     4.740] (II) The server relies on udev to provide the list of input devices.
	If no devices become available, reconfigure udev or disable AutoAddDevices.
[     4.740] (II) Module ABI versions:
[     4.740] 	X.Org ANSI C Emulation: 0.4
[     4.740] 	X.Org Video Driver: 25.2
[     4.740] 	X.Org XInput driver : 24.4
[     4.740] 	X.Org Server Extension : 10.0
[     4.741] (++) using VT number 1

[     4.742] (II) systemd-logind: took control of session /org/freedesktop/login1/session/_31
[     4.742] (II) xfree86: Adding drm device (/dev/dri/card1)
[     4.742] (II) Platform probe for /sys/devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm/card1
[     4.742] (II) systemd-logind: got fd for /dev/dri/card1 226:1 fd 14 paused 0
[     4.742] (II) xfree86: Adding drm device (/dev/dri/card0)
[     4.742] (II) Platform probe for /sys/devices/pci0000:00/0000:00:08.1/0000:06:00.0/drm/card0
[     4.743] (II) systemd-logind: got fd for /dev/dri/card0 226:0 fd 15 paused 0
[     4.744] (**) OutputClass "nvidia" ModulePath extended to "/usr/lib/nvidia/xorg,/usr/lib/xorg/modules,/usr/lib/xorg/modules"
[     5.047] (--) PCI: (1@0:0:0) 10de:2520:1043:16a2 rev 161, Mem @ 0xfb000000/16777216, 0xfc00000000/8589934592, 0xfe00000000/33554432, I/O @ 0x0000f000/128, BIOS @ 0x????????/524288
[     5.047] (--) PCI:*(6@0:0:0) 1002:1638:1043:16a2 rev 197, Mem @ 0xfe10000000/268435456, 0xfe20000000/2097152, 0xfc500000/524288, I/O @ 0x0000d000/256
[     5.047] (WW) Open ACPI failed (/var/run/acpid.socket) (No such file or directory)
[     5.047] (II) LoadModule: "glx"
[     5.056] (II) Loading /usr/lib/xorg/modules/extensions/libglx.so
[     5.059] (II) Module glx: vendor="X.Org Foundation"
[     5.059] 	compiled for 1.21.1.4, module version = 1.0.0
[     5.059] 	ABI class: X.Org Server Extension, version 10.0
[     5.059] (II) Applying OutputClass "AMDgpu" to /dev/dri/card0
[     5.059] 	loading driver: amdgpu
[     5.059] (II) Applying OutputClass "nvidia" to /dev/dri/card1
[     5.059] 	loading driver: nvidia
[     5.059] (==) Matched amdgpu as autoconfigured driver 0
[     5.059] (==) Matched ati as autoconfigured driver 1
[     5.059] (==) Matched nvidia as autoconfigured driver 2
[     5.059] (==) Matched nouveau as autoconfigured driver 3
[     5.059] (==) Matched nv as autoconfigured driver 4
[     5.059] (==) Matched modesetting as autoconfigured driver 5
[     5.059] (==) Matched fbdev as autoconfigured driver 6
[     5.059] (==) Matched vesa as autoconfigured driver 7
[     5.059] (==) Assigned the driver to the xf86ConfigLayout
[     5.059] (II) LoadModule: "amdgpu"
[     5.059] (II) Loading /usr/lib/xorg/modules/drivers/amdgpu_drv.so
[     5.060] (II) Module amdgpu: vendor="X.Org Foundation"
[     5.060] 	compiled for 1.21.1.3, module version = 22.0.0
[     5.060] 	Module class: X.Org Video Driver
[     5.060] 	ABI class: X.Org Video Driver, version 25.2
[     5.060] (II) LoadModule: "ati"
[     5.060] (WW) Warning, couldn't open module ati
[     5.060] (EE) Failed to load module "ati" (module does not exist, 0)
[     5.060] (II) LoadModule: "nvidia"
[     5.061] (II) Loading /usr/lib/xorg/modules/drivers/nvidia_drv.so
[     5.062] (II) Module nvidia: vendor="NVIDIA Corporation"
[     5.063] 	compiled for 1.6.99.901, module version = 1.0.0
[     5.063] 	Module class: X.Org Video Driver
[     5.063] (II) LoadModule: "nouveau"
[     5.063] (WW) Warning, couldn't open module nouveau
[     5.063] (EE) Failed to load module "nouveau" (module does not exist, 0)
[     5.063] (II) LoadModule: "nv"
[     5.063] (WW) Warning, couldn't open module nv
[     5.063] (EE) Failed to load module "nv" (module does not exist, 0)
[     5.063] (II) LoadModule: "modesetting"
[     5.063] (II) Loading /usr/lib/xorg/modules/drivers/modesetting_drv.so
[     5.063] (II) Module modesetting: vendor="X.Org Foundation"
[     5.063] 	compiled for 1.21.1.4, module version = 1.21.1
[     5.063] 	Module class: X.Org Video Driver
[     5.063] 	ABI class: X.Org Video Driver, version 25.2
[     5.063] (II) LoadModule: "fbdev"
[     5.063] (II) Loading /usr/lib/xorg/modules/drivers/fbdev_drv.so
[     5.064] (II) Module fbdev: vendor="X.Org Foundation"
[     5.064] 	compiled for 1.21.1.1, module version = 0.5.0
[     5.064] 	Module class: X.Org Video Driver
[     5.064] 	ABI class: X.Org Video Driver, version 25.2
[     5.064] (II) LoadModule: "vesa"
[     5.064] (II) Loading /usr/lib/xorg/modules/drivers/vesa_drv.so
[     5.064] (II) Module vesa: vendor="X.Org Foundation"
[     5.064] 	compiled for 1.21.1.3, module version = 2.5.0
[     5.064] 	Module class: X.Org Video Driver
[     5.064] 	ABI class: X.Org Video Driver, version 25.2
[     5.064] (II) AMDGPU: Driver for AMD Radeon:
	All GPUs supported by the amdgpu kernel driver
[     5.064] (II) NVIDIA dlloader X Driver  520.56.06  Thu Oct  6 21:29:26 UTC 2022
[     5.064] (II) NVIDIA Unified Driver for all Supported NVIDIA GPUs
[     5.064] (II) modesetting: Driver for Modesetting Kernel Drivers: kms
[     5.064] (II) FBDEV: driver for framebuffer: fbdev
[     5.064] (II) VESA: driver for VESA chipsets: vesa
[     5.068] (WW) Falling back to old probe method for modesetting
[     5.068] (WW) Falling back to old probe method for fbdev
[     5.068] (II) Loading sub module "fbdevhw"
[     5.068] (II) LoadModule: "fbdevhw"
[     5.068] (II) Loading /usr/lib/xorg/modules/libfbdevhw.so
[     5.068] (II) Module fbdevhw: vendor="X.Org Foundation"
[     5.068] 	compiled for 1.21.1.4, module version = 0.0.2
[     5.068] 	ABI class: X.Org Video Driver, version 25.2
[     5.068] (II) systemd-logind: releasing fd for 226:1
[     5.069] (II) Loading sub module "fb"
[     5.069] (II) LoadModule: "fb"
[     5.069] (II) Module "fb" already built-in
[     5.069] (II) Loading sub module "wfb"
[     5.069] (II) LoadModule: "wfb"
[     5.069] (II) Loading /usr/lib/xorg/modules/libwfb.so
[     5.069] (II) Module wfb: vendor="X.Org Foundation"
[     5.069] 	compiled for 1.21.1.4, module version = 1.0.0
[     5.069] 	ABI class: X.Org ANSI C Emulation, version 0.4
[     5.069] (II) Loading sub module "ramdac"
[     5.069] (II) LoadModule: "ramdac"
[     5.069] (II) Module "ramdac" already built-in
[     5.070] (II) AMDGPU(0): Creating default Display subsection in Screen section
	"Default Screen Section" for depth/fbbpp 24/32
[     5.070] (==) AMDGPU(0): Depth 24, (--) framebuffer bpp 32
[     5.070] (II) AMDGPU(0): Pixel depth = 24 bits stored in 4 bytes (32 bpp pixmaps)
[     5.070] (==) AMDGPU(0): Default visual is TrueColor
[     5.070] (==) AMDGPU(0): RGB weight 888
[     5.070] (II) AMDGPU(0): Using 8 bits per RGB (8 bit DAC)
[     5.070] (--) AMDGPU(0): Chipset: "Unknown AMD Radeon GPU" (ChipID = 0x1638)
[     5.070] (II) Loading sub module "fb"
[     5.070] (II) LoadModule: "fb"
[     5.070] (II) Module "fb" already built-in
[     5.070] (II) Loading sub module "dri2"
[     5.070] (II) LoadModule: "dri2"
[     5.070] (II) Module "dri2" already built-in
[     5.168] (II) Loading sub module "glamoregl"
[     5.168] (II) LoadModule: "glamoregl"
[     5.168] (II) Loading /usr/lib/xorg/modules/libglamoregl.so
[     5.171] (II) Module glamoregl: vendor="X.Org Foundation"
[     5.171] 	compiled for 1.21.1.4, module version = 1.0.1
[     5.171] 	ABI class: X.Org ANSI C Emulation, version 0.4
[     6.633] (II) AMDGPU(0): glamor X acceleration enabled on RENOIR (renoir, LLVM 14.0.6, DRM 3.48, 6.0.1-arch2-1)
[     6.633] (II) AMDGPU(0): glamor detected, initialising EGL layer.
[     6.633] (==) AMDGPU(0): TearFree property default: auto
[     6.633] (==) AMDGPU(0): VariableRefresh: disabled
[     6.633] (==) AMDGPU(0): AsyncFlipSecondaries: disabled
[     6.633] (II) AMDGPU(0): KMS Pageflipping: enabled
[     6.635] (II) AMDGPU(0): Output eDP has no monitor section
[     6.637] (II) AMDGPU(0): Output HDMI-A-0 has no monitor section
[     6.665] (II) AMDGPU(0): EDID for output eDP
[     6.665] (II) AMDGPU(0): Manufacturer: NCP  Model: 4d  Serial#: 0
[     6.665] (II) AMDGPU(0): Year: 2019  Week: 51
[     6.665] (II) AMDGPU(0): EDID Version: 1.4
[     6.665] (II) AMDGPU(0): Digital Display Input
[     6.665] (II) AMDGPU(0): 8 bits per channel
[     6.665] (II) AMDGPU(0): Digital interface is DisplayPort
[     6.665] (II) AMDGPU(0): Max Image Size [cm]: horiz.: 34  vert.: 19
[     6.665] (II) AMDGPU(0): Gamma: 2.20
[     6.665] (II) AMDGPU(0): No DPMS capabilities specified
[     6.665] (II) AMDGPU(0): Supported color encodings: RGB 4:4:4 
[     6.665] (II) AMDGPU(0): First detailed timing is preferred mode
[     6.665] (II) AMDGPU(0): Preferred mode is native pixel format and refresh rate
[     6.665] (II) AMDGPU(0): Display is continuous-frequency
[     6.665] (II) AMDGPU(0): redX: 0.595 redY: 0.361   greenX: 0.346 greenY: 0.555
[     6.665] (II) AMDGPU(0): blueX: 0.157 blueY: 0.106   whiteX: 0.312 whiteY: 0.328
[     6.665] (II) AMDGPU(0): Manufacturer's mask: 0
[     6.665] (II) AMDGPU(0): Supported detailed timing:
[     6.665] (II) AMDGPU(0): clock: 354.7 MHz   Image Size:  344 x 194 mm
[     6.665] (II) AMDGPU(0): h_active: 1920  h_sync: 1968  h_sync_end 2000 h_blank_end 2180 h_border: 0
[     6.665] (II) AMDGPU(0): v_active: 1080  v_sync: 1083  v_sync_end 1088 v_blanking: 1130 v_border: 0
[     6.665] (II) AMDGPU(0): Supported detailed timing:
[     6.665] (II) AMDGPU(0): clock: 147.8 MHz   Image Size:  344 x 194 mm
[     6.665] (II) AMDGPU(0): h_active: 1920  h_sync: 1968  h_sync_end 2000 h_blank_end 2180 h_border: 0
[     6.665] (II) AMDGPU(0): v_active: 1080  v_sync: 1083  v_sync_end 1088 v_blanking: 1130 v_border: 0
[     6.665] (II) AMDGPU(0): Ranges: V min: 48 V max: 144 Hz, H min: 163 H max: 163 kHz, PixClock max 355 MHz
[     6.665] (II) AMDGPU(0):  LM156LF-2F03
[     6.665] (II) AMDGPU(0): EDID (in hex):
[     6.665] (II) AMDGPU(0): 	00ffffffffffff0038704d0000000000
[     6.665] (II) AMDGPU(0): 	331d0104a5221378036850985c588e28
[     6.665] (II) AMDGPU(0): 	1b505400000001010101010101010101
[     6.665] (II) AMDGPU(0): 	010101010101918a8004713832403020
[     6.665] (II) AMDGPU(0): 	350058c21000001abd39800471383240
[     6.665] (II) AMDGPU(0): 	3020350058c21000001a000000fd0030
[     6.665] (II) AMDGPU(0): 	90a3a323010a202020202020000000fe
[     6.665] (II) AMDGPU(0): 	004c4d3135364c462d324630330a0035
[     6.665] (II) AMDGPU(0): Printing probed modes for output eDP
[     6.665] (II) AMDGPU(0): Modeline "1920x1080"x144.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[     6.665] (II) AMDGPU(0): Modeline "1920x1080"x120.0  354.73  1920 1968 2000 2180  1080 1309 1314 1356 +hsync -vsync (162.7 kHz e)
[     6.665] (II) AMDGPU(0): Modeline "1920x1080"x96.0  354.73  1920 1968 2000 2180  1080 1648 1653 1695 +hsync -vsync (162.7 kHz e)
[     6.665] (II) AMDGPU(0): Modeline "1920x1080"x72.0  354.73  1920 1968 2000 2180  1080 2213 2218 2260 +hsync -vsync (162.7 kHz e)
[     6.665] (II) AMDGPU(0): Modeline "1920x1080"x60.0  354.73  1920 1968 2000 2180  1080 2665 2670 2712 +hsync -vsync (162.7 kHz e)
[     6.665] (II) AMDGPU(0): Modeline "1920x1080"x50.0  354.73  1920 1968 2000 2180  1080 3207 3212 3254 +hsync -vsync (162.7 kHz e)
[     6.665] (II) AMDGPU(0): Modeline "1920x1080"x48.0  354.73  1920 1968 2000 2180  1080 3343 3348 3390 +hsync -vsync (162.7 kHz e)
[     6.665] (II) AMDGPU(0): Modeline "1920x1080"x60.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[     6.665] (II) AMDGPU(0): Modeline "1680x1050"x144.0  354.73  1680 1968 2000 2180  1050 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[     6.665] (II) AMDGPU(0): Modeline "1280x1024"x144.0  354.73  1280 1968 2000 2180  1024 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[     6.665] (II) AMDGPU(0): Modeline "1440x900"x144.0  354.73  1440 1968 2000 2180  900 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[     6.665] (II) AMDGPU(0): Modeline "1280x800"x144.0  354.73  1280 1968 2000 2180  800 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[     6.665] (II) AMDGPU(0): Modeline "1280x720"x144.0  354.73  1280 1968 2000 2180  720 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[     6.665] (II) AMDGPU(0): Modeline "1024x768"x144.0  354.73  1024 1968 2000 2180  768 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[     6.665] (II) AMDGPU(0): Modeline "800x600"x144.0  354.73  800 1968 2000 2180  600 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[     6.665] (II) AMDGPU(0): Modeline "640x480"x144.0  354.73  640 1968 2000 2180  480 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[     6.667] (II) AMDGPU(0): EDID for output HDMI-A-0
[     6.667] (II) AMDGPU(0): Manufacturer: SAM  Model: c4e  Serial#: 1113216587
[     6.667] (II) AMDGPU(0): Year: 2020  Week: 41
[     6.667] (II) AMDGPU(0): EDID Version: 1.3
[     6.667] (II) AMDGPU(0): Digital Display Input
[     6.667] (II) AMDGPU(0): Max Image Size [cm]: horiz.: 61  vert.: 35
[     6.667] (II) AMDGPU(0): Gamma: 2.20
[     6.667] (II) AMDGPU(0): DPMS capabilities: Off
[     6.667] (II) AMDGPU(0): Supported color encodings: RGB 4:4:4 YCrCb 4:4:4 
[     6.667] (II) AMDGPU(0): First detailed timing is preferred mode
[     6.667] (II) AMDGPU(0): redX: 0.634 redY: 0.341   greenX: 0.312 greenY: 0.636
[     6.667] (II) AMDGPU(0): blueX: 0.158 blueY: 0.062   whiteX: 0.312 whiteY: 0.329
[     6.667] (II) AMDGPU(0): Supported established timings:
[     6.667] (II) AMDGPU(0): 720x400@70Hz
[     6.667] (II) AMDGPU(0): 640x480@60Hz
[     6.667] (II) AMDGPU(0): 640x480@67Hz
[     6.667] (II) AMDGPU(0): 640x480@72Hz
[     6.667] (II) AMDGPU(0): 640x480@75Hz
[     6.667] (II) AMDGPU(0): 800x600@56Hz
[     6.667] (II) AMDGPU(0): 800x600@60Hz
[     6.667] (II) AMDGPU(0): 800x600@72Hz
[     6.667] (II) AMDGPU(0): 800x600@75Hz
[     6.667] (II) AMDGPU(0): 832x624@75Hz
[     6.667] (II) AMDGPU(0): 1024x768@60Hz
[     6.667] (II) AMDGPU(0): 1024x768@70Hz
[     6.667] (II) AMDGPU(0): 1024x768@75Hz
[     6.667] (II) AMDGPU(0): 1280x1024@75Hz
[     6.667] (II) AMDGPU(0): 1152x864@75Hz
[     6.667] (II) AMDGPU(0): Manufacturer's mask: 0
[     6.667] (II) AMDGPU(0): Supported standard timings:
[     6.667] (II) AMDGPU(0): #0: hsize: 1152  vsize 864  refresh: 75  vid: 20337
[     6.667] (II) AMDGPU(0): #1: hsize: 1280  vsize 800  refresh: 60  vid: 129
[     6.667] (II) AMDGPU(0): #2: hsize: 1280  vsize 720  refresh: 60  vid: 49281
[     6.667] (II) AMDGPU(0): #3: hsize: 1280  vsize 1024  refresh: 60  vid: 32897
[     6.667] (II) AMDGPU(0): #4: hsize: 1440  vsize 900  refresh: 60  vid: 149
[     6.667] (II) AMDGPU(0): #5: hsize: 1600  vsize 900  refresh: 60  vid: 49321
[     6.667] (II) AMDGPU(0): #6: hsize: 1680  vsize 1050  refresh: 60  vid: 179
[     6.667] (II) AMDGPU(0): Supported detailed timing:
[     6.667] (II) AMDGPU(0): clock: 297.0 MHz   Image Size:  608 x 345 mm
[     6.667] (II) AMDGPU(0): h_active: 3840  h_sync: 4016  h_sync_end 4104 h_blank_end 4400 h_border: 0
[     6.667] (II) AMDGPU(0): v_active: 2160  v_sync: 2168  v_sync_end 2178 v_blanking: 2250 v_border: 0
[     6.667] (II) AMDGPU(0): Ranges: V min: 24 V max: 75 Hz, H min: 30 H max: 90 kHz, PixClock max 305 MHz
[     6.667] (II) AMDGPU(0): Monitor name: U28E590
[     6.667] (II) AMDGPU(0): Serial No: H4ZNA00044
[     6.667] (II) AMDGPU(0): Supported detailed timing:
[     6.667] (II) AMDGPU(0): clock: 148.5 MHz   Image Size:  608 x 345 mm
[     6.667] (II) AMDGPU(0): h_active: 1920  h_sync: 2008  h_sync_end 2052 h_blank_end 2200 h_border: 0
[     6.667] (II) AMDGPU(0): v_active: 1080  v_sync: 1084  v_sync_end 1089 v_blanking: 1125 v_border: 0
[     6.667] (II) AMDGPU(0): Supported detailed timing:
[     6.667] (II) AMDGPU(0): clock: 148.5 MHz   Image Size:  608 x 345 mm
[     6.667] (II) AMDGPU(0): h_active: 1920  h_sync: 2448  h_sync_end 2492 h_blank_end 2640 h_border: 0
[     6.667] (II) AMDGPU(0): v_active: 1080  v_sync: 1084  v_sync_end 1089 v_blanking: 1125 v_border: 0
[     6.667] (II) AMDGPU(0): Supported detailed timing:
[     6.667] (II) AMDGPU(0): clock: 74.2 MHz   Image Size:  608 x 345 mm
[     6.667] (II) AMDGPU(0): h_active: 1280  h_sync: 1390  h_sync_end 1430 h_blank_end 1650 h_border: 0
[     6.667] (II) AMDGPU(0): v_active: 720  v_sync: 725  v_sync_end 730 v_blanking: 750 v_border: 0
[     6.667] (II) AMDGPU(0): Supported detailed timing:
[     6.667] (II) AMDGPU(0): clock: 241.5 MHz   Image Size:  608 x 345 mm
[     6.667] (II) AMDGPU(0): h_active: 2560  h_sync: 2608  h_sync_end 2640 h_blank_end 2720 h_border: 0
[     6.667] (II) AMDGPU(0): v_active: 1440  v_sync: 1443  v_sync_end 1448 v_blanking: 1481 v_border: 0
[     6.667] (II) AMDGPU(0): Number of EDID sections to follow: 1
[     6.667] (II) AMDGPU(0): EDID (in hex):
[     6.667] (II) AMDGPU(0): 	00ffffffffffff004c2d4e0c4b565a42
[     6.667] (II) AMDGPU(0): 	291e0103803d23782a5fb1a2574fa228
[     6.667] (II) AMDGPU(0): 	0f5054bfef80714f810081c081809500
[     6.667] (II) AMDGPU(0): 	a9c0b300010104740030f2705a80b058
[     6.667] (II) AMDGPU(0): 	8a0060592100001e000000fd00184b1e
[     6.667] (II) AMDGPU(0): 	5a1e000a202020202020000000fc0055
[     6.667] (II) AMDGPU(0): 	3238453539300a2020202020000000ff
[     6.667] (II) AMDGPU(0): 	0048345a4e4130303034340a202001d3
[     6.667] (II) AMDGPU(0): 	020324f0495f10041f13031220222309
[     6.667] (II) AMDGPU(0): 	0707830100006d030c001000803c2010
[     6.667] (II) AMDGPU(0): 	60010203023a801871382d40582c4500
[     6.667] (II) AMDGPU(0): 	60592100001e023a80d072382d40102c
[     6.667] (II) AMDGPU(0): 	458060592100001e011d007251d01e20
[     6.667] (II) AMDGPU(0): 	6e28550060592100001e565e00a0a0a0
[     6.667] (II) AMDGPU(0): 	29503020350060592100001a00000000
[     6.667] (II) AMDGPU(0): 	00000000000000000000000000000067
[     6.667] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[     6.667] (II) AMDGPU(0): Printing probed modes for output HDMI-A-0
[     6.667] (II) AMDGPU(0): Modeline "3840x2160"x30.0  297.00  3840 4016 4104 4400  2160 2168 2178 2250 +hsync +vsync (67.5 kHz eP)
[     6.667] (II) AMDGPU(0): Modeline "3840x2160"x25.0  297.00  3840 4896 4984 5280  2160 2168 2178 2250 +hsync +vsync (56.2 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "3840x2160"x24.0  297.00  3840 5116 5204 5500  2160 2168 2178 2250 +hsync +vsync (54.0 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "3840x2160"x30.0  296.70  3840 4016 4104 4400  2160 2168 2178 2250 +hsync +vsync (67.4 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "3840x2160"x24.0  296.70  3840 5116 5204 5500  2160 2168 2178 2250 +hsync +vsync (53.9 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "2560x1440"x60.0  241.50  2560 2608 2640 2720  1440 1443 1448 1481 +hsync -vsync (88.8 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1920x1200"x30.0  297.00  1920 4016 4104 4400  1200 2168 2178 2250 +hsync +vsync (67.5 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1920x1080"x60.0  148.50  1920 2008 2052 2200  1080 1084 1089 1125 +hsync +vsync (67.5 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1920x1080"x50.0  148.50  1920 2448 2492 2640  1080 1084 1089 1125 +hsync +vsync (56.2 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1920x1080"x59.9  148.35  1920 2008 2052 2200  1080 1084 1089 1125 +hsync +vsync (67.4 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1920x1080"x30.0   74.25  1920 2008 2052 2200  1080 1084 1089 1125 +hsync +vsync (33.8 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1920x1080"x24.0   74.25  1920 2558 2602 2750  1080 1084 1089 1125 +hsync +vsync (27.0 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1920x1080"x30.0   74.18  1920 2008 2052 2200  1080 1084 1089 1125 +hsync +vsync (33.7 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1920x1080"x24.0   74.18  1920 2558 2602 2750  1080 1084 1089 1125 +hsync +vsync (27.0 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1600x1200"x30.0  297.00  1600 4016 4104 4400  1200 2168 2178 2250 +hsync +vsync (67.5 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1680x1050"x59.9  119.00  1680 1728 1760 1840  1050 1053 1059 1080 +hsync -vsync (64.7 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1600x900"x60.0  108.00  1600 1624 1704 1800  900 901 904 1000 +hsync +vsync (60.0 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1280x1024"x75.0  135.00  1280 1296 1440 1688  1024 1025 1028 1066 +hsync +vsync (80.0 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1280x1024"x60.0  108.00  1280 1328 1440 1688  1024 1025 1028 1066 +hsync +vsync (64.0 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1440x900"x59.9   88.75  1440 1488 1520 1600  900 903 909 926 +hsync -vsync (55.5 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1280x800"x59.9   71.00  1280 1328 1360 1440  800 803 809 823 +hsync -vsync (49.3 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1152x864"x75.0  108.00  1152 1216 1344 1600  864 865 868 900 +hsync +vsync (67.5 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1280x720"x60.0   74.25  1280 1390 1430 1650  720 725 730 750 +hsync +vsync (45.0 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1280x720"x50.0   74.25  1280 1720 1760 1980  720 725 730 750 +hsync +vsync (37.5 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1280x720"x59.9   74.18  1280 1390 1430 1650  720 725 730 750 +hsync +vsync (45.0 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1024x768"x75.0   78.75  1024 1040 1136 1312  768 769 772 800 +hsync +vsync (60.0 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1024x768"x70.1   75.00  1024 1048 1184 1328  768 771 777 806 -hsync -vsync (56.5 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "1024x768"x60.0   65.00  1024 1048 1184 1344  768 771 777 806 -hsync -vsync (48.4 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "832x624"x74.6   57.28  832 864 928 1152  624 625 628 667 -hsync -vsync (49.7 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "800x600"x72.2   50.00  800 856 976 1040  600 637 643 666 +hsync +vsync (48.1 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "800x600"x75.0   49.50  800 816 896 1056  600 601 604 625 +hsync +vsync (46.9 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "800x600"x60.3   40.00  800 840 968 1056  600 601 605 628 +hsync +vsync (37.9 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "800x600"x56.2   36.00  800 824 896 1024  600 601 603 625 +hsync +vsync (35.2 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "720x576"x50.0   27.00  720 732 796 864  576 581 586 625 -hsync -vsync (31.2 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "720x480"x60.0   27.03  720 736 798 858  480 489 495 525 -hsync -vsync (31.5 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "720x480"x59.9   27.00  720 736 798 858  480 489 495 525 -hsync -vsync (31.5 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "640x480"x75.0   31.50  640 656 720 840  480 481 484 500 -hsync -vsync (37.5 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "640x480"x72.8   31.50  640 664 704 832  480 489 492 520 -hsync -vsync (37.9 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "640x480"x66.7   30.24  640 704 768 864  480 483 486 525 -hsync -vsync (35.0 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "640x480"x60.0   25.20  640 656 752 800  480 490 492 525 -hsync -vsync (31.5 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "640x480"x59.9   25.18  640 656 752 800  480 490 492 525 -hsync -vsync (31.5 kHz e)
[     6.667] (II) AMDGPU(0): Modeline "720x400"x70.1   28.32  720 738 846 900  400 412 414 449 -hsync +vsync (31.5 kHz e)
[     6.667] (II) AMDGPU(0): Output eDP connected
[     6.667] (II) AMDGPU(0): Output HDMI-A-0 connected
[     6.667] (II) AMDGPU(0): Using spanning desktop for initial modes
[     6.667] (II) AMDGPU(0): Output eDP using initial mode 1920x1080 +0+0
[     6.667] (II) AMDGPU(0): Output HDMI-A-0 using initial mode 3840x2160 +1920+0
[     6.667] (II) AMDGPU(0): mem size init: gart size :7c641d000 vram size: s:1c771000 visible:1c771000
[     6.667] (==) AMDGPU(0): DPI set to (96, 96)
[     6.667] (==) AMDGPU(0): Using gamma correction (1.0, 1.0, 1.0)
[     6.667] (II) Loading sub module "ramdac"
[     6.667] (II) LoadModule: "ramdac"
[     6.667] (II) Module "ramdac" already built-in
[     6.667] (==) NVIDIA(G0): Depth 24, (==) framebuffer bpp 32
[     6.667] (==) NVIDIA(G0): RGB weight 888
[     6.667] (==) NVIDIA(G0): Default visual is TrueColor
[     6.667] (==) NVIDIA(G0): Using gamma correction (1.0, 1.0, 1.0)
[     6.667] (II) Applying OutputClass "nvidia" options to /dev/dri/card1
[     6.668] (**) NVIDIA(G0): Option "AllowEmptyInitialConfiguration"
[     6.668] (**) NVIDIA(G0): Enabling 2D acceleration
[     6.668] (II) Loading sub module "glxserver_nvidia"
[     6.668] (II) LoadModule: "glxserver_nvidia"
[     6.668] (II) Loading /usr/lib/nvidia/xorg/libglxserver_nvidia.so
[     6.683] (II) Module glxserver_nvidia: vendor="NVIDIA Corporation"
[     6.683] 	compiled for 1.6.99.901, module version = 1.0.0
[     6.683] 	Module class: X.Org Server Extension
[     6.683] (II) NVIDIA GLX Module  520.56.06  Thu Oct  6 21:26:26 UTC 2022
[     6.684] (II) NVIDIA: The X server supports PRIME Render Offload.
[     6.697] (--) NVIDIA(0): Valid display device(s) on GPU-0 at PCI:1:0:0
[     6.697] (--) NVIDIA(0):     DFP-0
[     6.697] (--) NVIDIA(0):     DFP-1
[     6.698] (II) NVIDIA(G0): NVIDIA GPU NVIDIA GeForce RTX 3060 Laptop GPU (GA106-A) at
[     6.698] (II) NVIDIA(G0):     PCI:1:0:0 (GPU-0)
[     6.698] (--) NVIDIA(G0): Memory: 6291456 kBytes
[     6.698] (--) NVIDIA(G0): VideoBIOS: 94.06.17.00.5f
[     6.698] (II) NVIDIA(G0): Detected PCI Express Link width: 16X
[     6.698] (--) NVIDIA(GPU-0): DFP-0: disconnected
[     6.698] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[     6.698] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[     6.698] (--) NVIDIA(GPU-0): 
[     6.698] (--) NVIDIA(GPU-0): DFP-1: disconnected
[     6.698] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[     6.698] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[     6.698] (--) NVIDIA(GPU-0): 
[     6.698] (II) NVIDIA(G0): Validated MetaModes:
[     6.698] (II) NVIDIA(G0):     "NULL"
[     6.698] (II) NVIDIA(G0): Virtual screen size determined to be 640 x 480
[     6.698] (WW) NVIDIA(G0): Unable to get display device for DPI computation.
[     6.698] (==) NVIDIA(G0): DPI set to (75, 75); computed from built-in default
[     6.698] (II) UnloadModule: "modesetting"
[     6.698] (II) Unloading modesetting
[     6.699] (II) UnloadModule: "fbdev"
[     6.699] (II) Unloading fbdev
[     6.699] (II) UnloadSubModule: "fbdevhw"
[     6.699] (II) Unloading fbdevhw
[     6.699] (II) UnloadModule: "vesa"
[     6.699] (II) Unloading vesa
[     6.699] (II) AMDGPU(0): [DRI2] Setup complete
[     6.699] (II) AMDGPU(0): [DRI2]   DRI driver: radeonsi
[     6.699] (II) AMDGPU(0): [DRI2]   VDPAU driver: radeonsi
[     6.739] (II) AMDGPU(0): Front buffer pitch: 23040 bytes
[     6.740] (II) AMDGPU(0): SYNC extension fences enabled
[     6.740] (II) AMDGPU(0): Present extension enabled
[     6.740] (==) AMDGPU(0): DRI3 enabled
[     6.740] (==) AMDGPU(0): Backing store enabled
[     6.740] (II) AMDGPU(0): Direct rendering enabled
[     6.757] (II) AMDGPU(0): Use GLAMOR acceleration.
[     6.757] (II) AMDGPU(0): Acceleration enabled
[     6.757] (==) AMDGPU(0): DPMS enabled
[     6.757] (==) AMDGPU(0): Silken mouse enabled
[     6.757] (II) AMDGPU(0): Set up textured video (glamor)
[     6.797] (II) NVIDIA: Reserving 24576.00 MB of virtual memory for indirect memory
[     6.797] (II) NVIDIA:     access.
[     6.807] (II) NVIDIA(G0): ACPI: failed to connect to the ACPI event daemon; the daemon
[     6.807] (II) NVIDIA(G0):     may not be running or the "AcpidSocketPath" X
[     6.807] (II) NVIDIA(G0):     configuration option may not be set correctly.  When the
[     6.807] (II) NVIDIA(G0):     ACPI event daemon is available, the NVIDIA X driver will
[     6.807] (II) NVIDIA(G0):     try to use it to receive ACPI event notifications.  For
[     6.807] (II) NVIDIA(G0):     details, please see the "ConnectToAcpid" and
[     6.807] (II) NVIDIA(G0):     "AcpidSocketPath" X configuration options in Appendix B: X
[     6.807] (II) NVIDIA(G0):     Config Options in the README.
[     6.821] (II) NVIDIA(G0): Setting mode "NULL"
[     6.829] (==) NVIDIA(G0): Disabling shared memory pixmaps
[     6.829] (==) NVIDIA(G0): Backing store enabled
[     6.829] (==) NVIDIA(G0): Silken mouse enabled
[     6.829] (==) NVIDIA(G0): DPMS enabled
[     6.829] (II) Loading sub module "dri2"
[     6.829] (II) LoadModule: "dri2"
[     6.829] (II) Module "dri2" already built-in
[     6.829] (II) NVIDIA(G0): [DRI2] Setup complete
[     6.829] (II) NVIDIA(G0): [DRI2]   VDPAU driver: nvidia
[     6.829] (II) Initializing extension Generic Event Extension
[     6.829] (II) Initializing extension SHAPE
[     6.829] (II) Initializing extension MIT-SHM
[     6.829] (II) Initializing extension XInputExtension
[     6.829] (II) Initializing extension XTEST
[     6.829] (II) Initializing extension BIG-REQUESTS
[     6.830] (II) Initializing extension SYNC
[     6.830] (II) Initializing extension XKEYBOARD
[     6.830] (II) Initializing extension XC-MISC
[     6.830] (II) Initializing extension SECURITY
[     6.830] (II) Initializing extension XFIXES
[     6.830] (II) Initializing extension RENDER
[     6.830] (II) Initializing extension RANDR
[     6.830] (II) Initializing extension COMPOSITE
[     6.830] (II) Initializing extension DAMAGE
[     6.830] (II) Initializing extension MIT-SCREEN-SAVER
[     6.830] (II) Initializing extension DOUBLE-BUFFER
[     6.830] (II) Initializing extension RECORD
[     6.830] (II) Initializing extension DPMS
[     6.830] (II) Initializing extension Present
[     6.830] (II) Initializing extension DRI3
[     6.830] (II) Initializing extension X-Resource
[     6.831] (II) Initializing extension XVideo
[     6.831] (II) Initializing extension XVideo-MotionCompensation
[     6.831] (II) Initializing extension GLX
[     6.831] (II) Initializing extension GLX
[     6.831] (II) Indirect GLX disabled.
[     6.834] (II) AIGLX: Loaded and initialized radeonsi
[     6.834] (II) GLX: Initialized DRI2 GL provider for screen 0
[     6.834] (II) Initializing extension XFree86-VidModeExtension
[     6.834] (II) Initializing extension XFree86-DGA
[     6.834] (II) Initializing extension XFree86-DRI
[     6.834] (II) Initializing extension DRI2
[     6.834] (II) Initializing extension NV-GLX
[     6.834] (II) Initializing extension NV-CONTROL
[     6.834] (II) AMDGPU(0): Setting screen physical size to 1524 x 571
[     6.987] (II) config/udev: Adding input device Asus Wireless Radio Control (/dev/input/event4)
[     6.987] (**) Asus Wireless Radio Control: Applying InputClass "libinput keyboard catchall"
[     6.987] (II) LoadModule: "libinput"
[     6.987] (II) Loading /usr/lib/xorg/modules/input/libinput_drv.so
[     6.989] (II) Module libinput: vendor="X.Org Foundation"
[     6.989] 	compiled for 1.21.1.3, module version = 1.2.1
[     6.989] 	Module class: X.Org XInput Driver
[     6.989] 	ABI class: X.Org XInput driver, version 24.4
[     6.989] (II) Using input driver 'libinput' for 'Asus Wireless Radio Control'
[     6.990] (II) systemd-logind: got fd for /dev/input/event4 13:68 fd 48 paused 0
[     6.990] (**) Asus Wireless Radio Control: always reports core events
[     6.990] (**) Option "Device" "/dev/input/event4"
[     6.994] (II) event4  - Asus Wireless Radio Control: is tagged by udev as: Keyboard
[     6.994] (II) event4  - Asus Wireless Radio Control: device is a keyboard
[     6.995] (II) event4  - Asus Wireless Radio Control: device removed
[     6.995] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/ATK4002:00/input/input4/event4"
[     6.995] (II) XINPUT: Adding extended input device "Asus Wireless Radio Control" (type: KEYBOARD, id 6)
[     6.995] (II) event4  - Asus Wireless Radio Control: is tagged by udev as: Keyboard
[     6.995] (II) event4  - Asus Wireless Radio Control: device is a keyboard
[     6.995] (II) config/udev: Adding input device Video Bus (/dev/input/event5)
[     6.995] (**) Video Bus: Applying InputClass "libinput keyboard catchall"
[     6.995] (II) Using input driver 'libinput' for 'Video Bus'
[     6.996] (II) systemd-logind: got fd for /dev/input/event5 13:69 fd 51 paused 0
[     6.996] (**) Video Bus: always reports core events
[     6.996] (**) Option "Device" "/dev/input/event5"
[     6.996] (II) event5  - Video Bus: is tagged by udev as: Keyboard
[     6.996] (II) event5  - Video Bus: device is a keyboard
[     6.996] (II) event5  - Video Bus: device removed
[     6.996] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/PNP0A08:00/device:01/LNXVIDEO:00/input/input5/event5"
[     6.996] (II) XINPUT: Adding extended input device "Video Bus" (type: KEYBOARD, id 7)
[     6.997] (II) event5  - Video Bus: is tagged by udev as: Keyboard
[     6.997] (II) event5  - Video Bus: device is a keyboard
[     6.997] (II) config/udev: Adding input device Video Bus (/dev/input/event6)
[     6.997] (**) Video Bus: Applying InputClass "libinput keyboard catchall"
[     6.997] (II) Using input driver 'libinput' for 'Video Bus'
[     6.998] (II) systemd-logind: got fd for /dev/input/event6 13:70 fd 52 paused 0
[     6.998] (**) Video Bus: always reports core events
[     6.998] (**) Option "Device" "/dev/input/event6"
[     6.998] (II) event6  - Video Bus: is tagged by udev as: Keyboard
[     6.998] (II) event6  - Video Bus: device is a keyboard
[     6.998] (II) event6  - Video Bus: device removed
[     6.998] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/PNP0A08:00/device:0f/LNXVIDEO:01/input/input6/event6"
[     6.998] (II) XINPUT: Adding extended input device "Video Bus" (type: KEYBOARD, id 8)
[     6.999] (II) event6  - Video Bus: is tagged by udev as: Keyboard
[     6.999] (II) event6  - Video Bus: device is a keyboard
[     6.999] (II) config/udev: Adding input device Power Button (/dev/input/event0)
[     6.999] (**) Power Button: Applying InputClass "libinput keyboard catchall"
[     6.999] (II) Using input driver 'libinput' for 'Power Button'
[     6.999] (II) systemd-logind: got fd for /dev/input/event0 13:64 fd 53 paused 0
[     6.999] (**) Power Button: always reports core events
[     6.999] (**) Option "Device" "/dev/input/event0"
[     7.000] (II) event0  - Power Button: is tagged by udev as: Keyboard
[     7.000] (II) event0  - Power Button: device is a keyboard
[     7.000] (II) event0  - Power Button: device removed
[     7.000] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/PNP0C0C:00/input/input0/event0"
[     7.000] (II) XINPUT: Adding extended input device "Power Button" (type: KEYBOARD, id 9)
[     7.000] (II) event0  - Power Button: is tagged by udev as: Keyboard
[     7.000] (II) event0  - Power Button: device is a keyboard
[     7.001] (II) config/udev: Adding input device Lid Switch (/dev/input/event2)
[     7.001] (II) No input driver specified, ignoring this device.
[     7.001] (II) This device may have been added with another device file.
[     7.001] (II) config/udev: Adding input device Sleep Button (/dev/input/event1)
[     7.001] (**) Sleep Button: Applying InputClass "libinput keyboard catchall"
[     7.001] (II) Using input driver 'libinput' for 'Sleep Button'
[     7.001] (II) systemd-logind: got fd for /dev/input/event1 13:65 fd 54 paused 0
[     7.001] (**) Sleep Button: always reports core events
[     7.001] (**) Option "Device" "/dev/input/event1"
[     7.002] (II) event1  - Sleep Button: is tagged by udev as: Keyboard
[     7.002] (II) event1  - Sleep Button: device is a keyboard
[     7.002] (II) event1  - Sleep Button: device removed
[     7.002] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/PNP0C0E:00/input/input1/event1"
[     7.002] (II) XINPUT: Adding extended input device "Sleep Button" (type: KEYBOARD, id 10)
[     7.002] (II) event1  - Sleep Button: is tagged by udev as: Keyboard
[     7.002] (II) event1  - Sleep Button: device is a keyboard
[     7.002] (II) config/udev: Adding input device HDA NVidia HDMI/DP,pcm=3 (/dev/input/event15)
[     7.002] (II) No input driver specified, ignoring this device.
[     7.002] (II) This device may have been added with another device file.
[     7.003] (II) config/udev: Adding input device HDA NVidia HDMI/DP,pcm=7 (/dev/input/event16)
[     7.003] (II) No input driver specified, ignoring this device.
[     7.003] (II) This device may have been added with another device file.
[     7.003] (II) config/udev: Adding input device HDA NVidia HDMI/DP,pcm=8 (/dev/input/event17)
[     7.003] (II) No input driver specified, ignoring this device.
[     7.003] (II) This device may have been added with another device file.
[     7.003] (II) config/udev: Adding input device HDA NVidia HDMI/DP,pcm=9 (/dev/input/event18)
[     7.003] (II) No input driver specified, ignoring this device.
[     7.003] (II) This device may have been added with another device file.
[     7.003] (II) config/udev: Adding input device HD-Audio Generic HDMI/DP,pcm=3 (/dev/input/event14)
[     7.003] (II) No input driver specified, ignoring this device.
[     7.003] (II) This device may have been added with another device file.
[     7.004] (II) config/udev: Adding input device Logitech Wireless Keyboard PID:4023 (/dev/input/event13)
[     7.004] (**) Logitech Wireless Keyboard PID:4023: Applying InputClass "libinput keyboard catchall"
[     7.004] (II) Using input driver 'libinput' for 'Logitech Wireless Keyboard PID:4023'
[     7.004] (II) systemd-logind: got fd for /dev/input/event13 13:77 fd 55 paused 0
[     7.004] (**) Logitech Wireless Keyboard PID:4023: always reports core events
[     7.004] (**) Option "Device" "/dev/input/event13"
[     7.005] (II) event13 - Logitech Wireless Keyboard PID:4023: is tagged by udev as: Keyboard
[     7.005] (II) event13 - Logitech Wireless Keyboard PID:4023: device is a keyboard
[     7.005] (II) event13 - Logitech Wireless Keyboard PID:4023: device removed
[     7.005] (II) libinput: Logitech Wireless Keyboard PID:4023: needs a virtual subdevice
[     7.005] (**) Option "config_info" "udev:/sys/devices/pci0000:00/0000:00:08.1/0000:06:00.3/usb1/1-2/1-2:1.1/0003:046D:C534.0003/0003:046D:4023.0004/input/input35/event13"
[     7.005] (II) XINPUT: Adding extended input device "Logitech Wireless Keyboard PID:4023" (type: MOUSE, id 11)
[     7.005] (**) Option "AccelerationScheme" "none"
[     7.005] (**) Logitech Wireless Keyboard PID:4023: (accel) selected scheme none/0
[     7.005] (**) Logitech Wireless Keyboard PID:4023: (accel) acceleration factor: 2.000
[     7.005] (**) Logitech Wireless Keyboard PID:4023: (accel) acceleration threshold: 4
[     7.006] (II) event13 - Logitech Wireless Keyboard PID:4023: is tagged by udev as: Keyboard
[     7.006] (II) event13 - Logitech Wireless Keyboard PID:4023: device is a keyboard
[     7.006] (II) config/udev: Adding input device Logitech Wireless Mouse (/dev/input/event19)
[     7.006] (**) Logitech Wireless Mouse: Applying InputClass "libinput pointer catchall"
[     7.006] (II) Using input driver 'libinput' for 'Logitech Wireless Mouse'
[     7.006] (II) systemd-logind: got fd for /dev/input/event19 13:83 fd 56 paused 0
[     7.006] (**) Logitech Wireless Mouse: always reports core events
[     7.006] (**) Option "Device" "/dev/input/event19"
[     7.007] (II) event19 - Logitech Wireless Mouse: is tagged by udev as: Mouse
[     7.007] (II) event19 - Logitech Wireless Mouse: device is a pointer
[     7.007] (II) event19 - Logitech Wireless Mouse: device removed
[     7.007] (**) Option "config_info" "udev:/sys/devices/pci0000:00/0000:00:08.1/0000:06:00.3/usb1/1-2/1-2:1.1/0003:046D:C534.0003/0003:046D:4058.0005/input/input36/event19"
[     7.007] (II) XINPUT: Adding extended input device "Logitech Wireless Mouse" (type: MOUSE, id 12)
[     7.007] (**) Option "AccelerationScheme" "none"
[     7.007] (**) Logitech Wireless Mouse: (accel) selected scheme none/0
[     7.007] (**) Logitech Wireless Mouse: (accel) acceleration factor: 2.000
[     7.007] (**) Logitech Wireless Mouse: (accel) acceleration threshold: 4
[     7.008] (II) event19 - Logitech Wireless Mouse: is tagged by udev as: Mouse
[     7.008] (II) event19 - Logitech Wireless Mouse: device is a pointer
[     7.009] (II) config/udev: Adding input device Logitech Wireless Mouse (/dev/input/mouse2)
[     7.009] (II) No input driver specified, ignoring this device.
[     7.009] (II) This device may have been added with another device file.
[     7.009] (II) config/udev: Adding input device USB2.0 HD UVC WebCam: USB2.0 HD (/dev/input/event11)
[     7.009] (**) USB2.0 HD UVC WebCam: USB2.0 HD: Applying InputClass "libinput keyboard catchall"
[     7.009] (II) Using input driver 'libinput' for 'USB2.0 HD UVC WebCam: USB2.0 HD'
[     7.009] (II) systemd-logind: got fd for /dev/input/event11 13:75 fd 57 paused 0
[     7.009] (**) USB2.0 HD UVC WebCam: USB2.0 HD: always reports core events
[     7.009] (**) Option "Device" "/dev/input/event11"
[     7.010] (II) event11 - USB2.0 HD UVC WebCam: USB2.0 HD: is tagged by udev as: Keyboard
[     7.010] (II) event11 - USB2.0 HD UVC WebCam: USB2.0 HD: device is a keyboard
[     7.010] (II) event11 - USB2.0 HD UVC WebCam: USB2.0 HD: device removed
[     7.010] (**) Option "config_info" "udev:/sys/devices/pci0000:00/0000:00:08.1/0000:06:00.3/usb1/1-4/1-4:1.0/input/input25/event11"
[     7.010] (II) XINPUT: Adding extended input device "USB2.0 HD UVC WebCam: USB2.0 HD" (type: KEYBOARD, id 13)
[     7.011] (II) event11 - USB2.0 HD UVC WebCam: USB2.0 HD: is tagged by udev as: Keyboard
[     7.011] (II) event11 - USB2.0 HD UVC WebCam: USB2.0 HD: device is a keyboard
[     7.011] (II) config/udev: Adding input device HD-Audio Generic Headphone (/dev/input/event8)
[     7.011] (II) No input driver specified, ignoring this device.
[     7.011] (II) This device may have been added with another device file.
[     7.011] (II) config/udev: Adding input device ELAN1203:00 04F3:307A Mouse (/dev/input/event10)
[     7.011] (**) ELAN1203:00 04F3:307A Mouse: Applying InputClass "libinput pointer catchall"
[     7.011] (II) Using input driver 'libinput' for 'ELAN1203:00 04F3:307A Mouse'
[     7.011] (II) systemd-logind: got fd for /dev/input/event10 13:74 fd 58 paused 0
[     7.011] (**) ELAN1203:00 04F3:307A Mouse: always reports core events
[     7.011] (**) Option "Device" "/dev/input/event10"
[     7.012] (II) event10 - ELAN1203:00 04F3:307A Mouse: is tagged by udev as: Mouse Pointingstick
[     7.012] (II) event10 - ELAN1203:00 04F3:307A Mouse: device is a pointer
[     7.013] (II) event10 - ELAN1203:00 04F3:307A Mouse: device removed
[     7.013] (**) Option "config_info" "udev:/sys/devices/platform/AMDI0010:03/i2c-0/i2c-ELAN1203:00/0018:04F3:307A.0001/input/input23/event10"
[     7.013] (II) XINPUT: Adding extended input device "ELAN1203:00 04F3:307A Mouse" (type: MOUSE, id 14)
[     7.013] (**) Option "AccelerationScheme" "none"
[     7.013] (**) ELAN1203:00 04F3:307A Mouse: (accel) selected scheme none/0
[     7.013] (**) ELAN1203:00 04F3:307A Mouse: (accel) acceleration factor: 2.000
[     7.013] (**) ELAN1203:00 04F3:307A Mouse: (accel) acceleration threshold: 4
[     7.013] (II) event10 - ELAN1203:00 04F3:307A Mouse: is tagged by udev as: Mouse Pointingstick
[     7.014] (II) event10 - ELAN1203:00 04F3:307A Mouse: device is a pointer
[     7.014] (II) config/udev: Adding input device ELAN1203:00 04F3:307A Mouse (/dev/input/mouse0)
[     7.014] (II) No input driver specified, ignoring this device.
[     7.014] (II) This device may have been added with another device file.
[     7.014] (II) config/udev: Adding input device ELAN1203:00 04F3:307A Touchpad (/dev/input/event12)
[     7.014] (**) ELAN1203:00 04F3:307A Touchpad: Applying InputClass "libinput touchpad catchall"
[     7.014] (II) Using input driver 'libinput' for 'ELAN1203:00 04F3:307A Touchpad'
[     7.015] (II) systemd-logind: got fd for /dev/input/event12 13:76 fd 59 paused 0
[     7.015] (**) ELAN1203:00 04F3:307A Touchpad: always reports core events
[     7.015] (**) Option "Device" "/dev/input/event12"
[     7.015] (II) event12 - ELAN1203:00 04F3:307A Touchpad: is tagged by udev as: Touchpad
[     7.016] (II) event12 - ELAN1203:00 04F3:307A Touchpad: device is a touchpad
[     7.016] (II) event12 - ELAN1203:00 04F3:307A Touchpad: device removed
[     7.016] (**) Option "config_info" "udev:/sys/devices/platform/AMDI0010:03/i2c-0/i2c-ELAN1203:00/0018:04F3:307A.0001/input/input24/event12"
[     7.016] (II) XINPUT: Adding extended input device "ELAN1203:00 04F3:307A Touchpad" (type: TOUCHPAD, id 15)
[     7.017] (**) Option "AccelerationScheme" "none"
[     7.017] (**) ELAN1203:00 04F3:307A Touchpad: (accel) selected scheme none/0
[     7.017] (**) ELAN1203:00 04F3:307A Touchpad: (accel) acceleration factor: 2.000
[     7.017] (**) ELAN1203:00 04F3:307A Touchpad: (accel) acceleration threshold: 4
[     7.017] (II) event12 - ELAN1203:00 04F3:307A Touchpad: is tagged by udev as: Touchpad
[     7.018] (II) event12 - ELAN1203:00 04F3:307A Touchpad: device is a touchpad
[     7.018] (II) config/udev: Adding input device ELAN1203:00 04F3:307A Touchpad (/dev/input/mouse1)
[     7.018] (II) No input driver specified, ignoring this device.
[     7.018] (II) This device may have been added with another device file.
[     7.018] (II) config/udev: Adding input device Asus WMI hotkeys (/dev/input/event9)
[     7.018] (**) Asus WMI hotkeys: Applying InputClass "libinput keyboard catchall"
[     7.018] (II) Using input driver 'libinput' for 'Asus WMI hotkeys'
[     7.019] (II) systemd-logind: got fd for /dev/input/event9 13:73 fd 60 paused 0
[     7.019] (**) Asus WMI hotkeys: always reports core events
[     7.019] (**) Option "Device" "/dev/input/event9"
[     7.019] (II) event9  - Asus WMI hotkeys: is tagged by udev as: Keyboard
[     7.019] (II) event9  - Asus WMI hotkeys: device is a keyboard
[     7.019] (II) event9  - Asus WMI hotkeys: device removed
[     7.019] (**) Option "config_info" "udev:/sys/devices/platform/asus-nb-wmi/input/input22/event9"
[     7.019] (II) XINPUT: Adding extended input device "Asus WMI hotkeys" (type: KEYBOARD, id 16)
[     7.019] (II) event9  - Asus WMI hotkeys: is tagged by udev as: Keyboard
[     7.019] (II) event9  - Asus WMI hotkeys: device is a keyboard
[     7.020] (II) config/udev: Adding input device AT Translated Set 2 keyboard (/dev/input/event3)
[     7.020] (**) AT Translated Set 2 keyboard: Applying InputClass "libinput keyboard catchall"
[     7.020] (II) Using input driver 'libinput' for 'AT Translated Set 2 keyboard'
[     7.020] (II) systemd-logind: got fd for /dev/input/event3 13:67 fd 61 paused 0
[     7.020] (**) AT Translated Set 2 keyboard: always reports core events
[     7.020] (**) Option "Device" "/dev/input/event3"
[     7.021] (II) event3  - AT Translated Set 2 keyboard: is tagged by udev as: Keyboard
[     7.021] (II) event3  - AT Translated Set 2 keyboard: device is a keyboard
[     7.021] (II) event3  - AT Translated Set 2 keyboard: device removed
[     7.021] (**) Option "config_info" "udev:/sys/devices/platform/i8042/serio0/input/input3/event3"
[     7.021] (II) XINPUT: Adding extended input device "AT Translated Set 2 keyboard" (type: KEYBOARD, id 17)
[     7.022] (II) event3  - AT Translated Set 2 keyboard: is tagged by udev as: Keyboard
[     7.022] (II) event3  - AT Translated Set 2 keyboard: device is a keyboard
[     7.022] (II) config/udev: Adding input device PC Speaker (/dev/input/event7)
[     7.022] (II) No input driver specified, ignoring this device.
[     7.022] (II) This device may have been added with another device file.
[     7.033] (**) Logitech Wireless Keyboard PID:4023: Applying InputClass "libinput keyboard catchall"
[     7.033] (II) Using input driver 'libinput' for 'Logitech Wireless Keyboard PID:4023'
[     7.033] (II) systemd-logind: returning pre-existing fd for /dev/input/event13 13:77
[     7.033] (**) Logitech Wireless Keyboard PID:4023: always reports core events
[     7.033] (**) Option "Device" "/dev/input/event13"
[     7.033] (II) libinput: Logitech Wireless Keyboard PID:4023: is a virtual subdevice
[     7.033] (**) Option "config_info" "udev:/sys/devices/pci0000:00/0000:00:08.1/0000:06:00.3/usb1/1-2/1-2:1.1/0003:046D:C534.0003/0003:046D:4023.0004/input/input35/event13"
[     7.033] (II) XINPUT: Adding extended input device "Logitech Wireless Keyboard PID:4023" (type: KEYBOARD, id 18)
[     7.342] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[     7.342] (II) AMDGPU(0): Using EDID range info for horizontal sync
[     7.342] (II) AMDGPU(0): Using EDID range info for vertical refresh
[     7.342] (II) AMDGPU(0): Printing DDC gathered Modelines:
[     7.342] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[     7.342] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[     7.343] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[     7.345] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[     7.345] (II) AMDGPU(0): Using hsync ranges from config file
[     7.345] (II) AMDGPU(0): Using vrefresh ranges from config file
[     7.345] (II) AMDGPU(0): Printing DDC gathered Modelines:
[     7.346] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[     7.346] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[     7.347] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[     7.347] (--) NVIDIA(GPU-0): DFP-0: disconnected
[     7.347] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[     7.347] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[     7.347] (--) NVIDIA(GPU-0): 
[     7.347] (--) NVIDIA(GPU-0): DFP-1: disconnected
[     7.347] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[     7.347] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[     7.347] (--) NVIDIA(GPU-0): 
[     8.268] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[     8.268] (II) AMDGPU(0): Using hsync ranges from config file
[     8.268] (II) AMDGPU(0): Using vrefresh ranges from config file
[     8.268] (II) AMDGPU(0): Printing DDC gathered Modelines:
[     8.268] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[     8.268] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[     8.269] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[     8.271] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[     8.271] (II) AMDGPU(0): Using hsync ranges from config file
[     8.271] (II) AMDGPU(0): Using vrefresh ranges from config file
[     8.271] (II) AMDGPU(0): Printing DDC gathered Modelines:
[     8.271] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[     8.271] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[     8.273] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[     8.273] (--) NVIDIA(GPU-0): DFP-0: disconnected
[     8.273] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[     8.273] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[     8.273] (--) NVIDIA(GPU-0): 
[     8.273] (--) NVIDIA(GPU-0): DFP-1: disconnected
[     8.273] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[     8.273] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[     8.273] (--) NVIDIA(GPU-0): 
[     8.382] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[     8.382] (II) AMDGPU(0): Using hsync ranges from config file
[     8.382] (II) AMDGPU(0): Using vrefresh ranges from config file
[     8.382] (II) AMDGPU(0): Printing DDC gathered Modelines:
[     8.382] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[     8.382] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[     8.383] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[     8.385] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[     8.386] (II) AMDGPU(0): Using hsync ranges from config file
[     8.386] (II) AMDGPU(0): Using vrefresh ranges from config file
[     8.386] (II) AMDGPU(0): Printing DDC gathered Modelines:
[     8.386] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[     8.386] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[     8.387] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[     8.387] (--) NVIDIA(GPU-0): DFP-0: disconnected
[     8.387] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[     8.387] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[     8.387] (--) NVIDIA(GPU-0): 
[     8.387] (--) NVIDIA(GPU-0): DFP-1: disconnected
[     8.387] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[     8.387] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[     8.387] (--) NVIDIA(GPU-0): 
[   343.258] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[   343.258] (II) AMDGPU(0): Using hsync ranges from config file
[   343.258] (II) AMDGPU(0): Using vrefresh ranges from config file
[   343.258] (II) AMDGPU(0): Printing DDC gathered Modelines:
[   343.258] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[   343.258] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[   343.260] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[   343.260] (II) AMDGPU(0): Using hsync ranges from config file
[   343.260] (II) AMDGPU(0): Using vrefresh ranges from config file
[   343.260] (II) AMDGPU(0): Printing DDC gathered Modelines:
[   343.260] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[   343.260] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[   343.263] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[   343.263] (II) AMDGPU(0): Using hsync ranges from config file
[   343.263] (II) AMDGPU(0): Using vrefresh ranges from config file
[   343.263] (II) AMDGPU(0): Printing DDC gathered Modelines:
[   343.263] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[   343.263] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[   343.264] (--) NVIDIA(GPU-0): DFP-0: disconnected
[   343.264] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[   343.264] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[   343.264] (--) NVIDIA(GPU-0): 
[   343.264] (--) NVIDIA(GPU-0): DFP-1: disconnected
[   343.264] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[   343.264] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[   343.264] (--) NVIDIA(GPU-0): 
[   343.406] (EE) AMDGPU(0): drmmode_do_crtc_dpms cannot get last vblank counter
[   343.407] (II) AMDGPU(0): Allocate new frame buffer 1920x1080
[   343.407] (II) AMDGPU(0):  => pitch 7680 bytes
[   343.437] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[   343.437] (II) AMDGPU(0): Using hsync ranges from config file
[   343.437] (II) AMDGPU(0): Using vrefresh ranges from config file
[   343.437] (II) AMDGPU(0): Printing DDC gathered Modelines:
[   343.437] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[   343.437] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[   343.439] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[   343.439] (II) AMDGPU(0): Using hsync ranges from config file
[   343.439] (II) AMDGPU(0): Using vrefresh ranges from config file
[   343.439] (II) AMDGPU(0): Printing DDC gathered Modelines:
[   343.439] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[   343.439] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[   343.439] (--) NVIDIA(GPU-0): DFP-0: disconnected
[   343.439] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[   343.439] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[   343.439] (--) NVIDIA(GPU-0): 
[   343.439] (--) NVIDIA(GPU-0): DFP-1: disconnected
[   343.439] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[   343.439] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[   343.439] (--) NVIDIA(GPU-0): 
[   343.471] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[   343.471] (II) AMDGPU(0): Using hsync ranges from config file
[   343.471] (II) AMDGPU(0): Using vrefresh ranges from config file
[   343.471] (II) AMDGPU(0): Printing DDC gathered Modelines:
[   343.471] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[   343.471] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[   343.473] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[   343.473] (II) AMDGPU(0): Using hsync ranges from config file
[   343.473] (II) AMDGPU(0): Using vrefresh ranges from config file
[   343.473] (II) AMDGPU(0): Printing DDC gathered Modelines:
[   343.473] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[   343.473] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[   343.473] (--) NVIDIA(GPU-0): DFP-0: disconnected
[   343.473] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[   343.473] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[   343.473] (--) NVIDIA(GPU-0): 
[   343.473] (--) NVIDIA(GPU-0): DFP-1: disconnected
[   343.473] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[   343.473] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[   343.473] (--) NVIDIA(GPU-0): 
[   344.076] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[   344.076] (II) AMDGPU(0): Using hsync ranges from config file
[   344.076] (II) AMDGPU(0): Using vrefresh ranges from config file
[   344.076] (II) AMDGPU(0): Printing DDC gathered Modelines:
[   344.076] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[   344.076] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[   344.077] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[   344.079] (II) AMDGPU(0): Allocate new frame buffer 5760x2160
[   344.079] (II) AMDGPU(0):  => pitch 23040 bytes
[   344.189] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[   344.189] (II) AMDGPU(0): Using hsync ranges from config file
[   344.189] (II) AMDGPU(0): Using vrefresh ranges from config file
[   344.189] (II) AMDGPU(0): Printing DDC gathered Modelines:
[   344.189] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[   344.189] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[   344.190] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[   344.192] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[   344.192] (II) AMDGPU(0): Using hsync ranges from config file
[   344.192] (II) AMDGPU(0): Using vrefresh ranges from config file
[   344.192] (II) AMDGPU(0): Printing DDC gathered Modelines:
[   344.192] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[   344.192] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[   344.194] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[   344.194] (--) NVIDIA(GPU-0): DFP-0: disconnected
[   344.194] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[   344.194] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[   344.194] (--) NVIDIA(GPU-0): 
[   344.194] (--) NVIDIA(GPU-0): DFP-1: disconnected
[   344.194] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[   344.194] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[   344.194] (--) NVIDIA(GPU-0): 
[   344.346] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[   344.346] (II) AMDGPU(0): Using hsync ranges from config file
[   344.346] (II) AMDGPU(0): Using vrefresh ranges from config file
[   344.346] (II) AMDGPU(0): Printing DDC gathered Modelines:
[   344.346] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[   344.346] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[   344.349] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[   344.351] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[   344.351] (II) AMDGPU(0): Using hsync ranges from config file
[   344.351] (II) AMDGPU(0): Using vrefresh ranges from config file
[   344.351] (II) AMDGPU(0): Printing DDC gathered Modelines:
[   344.351] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[   344.351] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[   344.354] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[   344.355] (--) NVIDIA(GPU-0): DFP-0: disconnected
[   344.355] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[   344.355] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[   344.355] (--) NVIDIA(GPU-0): 
[   344.355] (--) NVIDIA(GPU-0): DFP-1: disconnected
[   344.355] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[   344.355] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[   344.355] (--) NVIDIA(GPU-0): 
[   344.396] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[   344.396] (II) AMDGPU(0): Using hsync ranges from config file
[   344.396] (II) AMDGPU(0): Using vrefresh ranges from config file
[   344.396] (II) AMDGPU(0): Printing DDC gathered Modelines:
[   344.396] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[   344.396] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[   344.399] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[   344.402] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[   344.402] (II) AMDGPU(0): Using hsync ranges from config file
[   344.402] (II) AMDGPU(0): Using vrefresh ranges from config file
[   344.402] (II) AMDGPU(0): Printing DDC gathered Modelines:
[   344.402] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[   344.402] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[   344.405] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[   344.405] (--) NVIDIA(GPU-0): DFP-0: disconnected
[   344.405] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[   344.405] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[   344.405] (--) NVIDIA(GPU-0): 
[   344.406] (--) NVIDIA(GPU-0): DFP-1: disconnected
[   344.406] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[   344.406] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[   344.406] (--) NVIDIA(GPU-0): 
[   349.214] (**) Option "fd" "48"
[   349.214] (II) event4  - Asus Wireless Radio Control: device removed
[   349.214] (**) Option "fd" "51"
[   349.214] (II) event5  - Video Bus: device removed
[   349.214] (**) Option "fd" "52"
[   349.215] (II) event6  - Video Bus: device removed
[   349.215] (**) Option "fd" "53"
[   349.215] (II) event0  - Power Button: device removed
[   349.215] (**) Option "fd" "54"
[   349.215] (II) event1  - Sleep Button: device removed
[   349.215] (**) Option "fd" "55"
[   349.215] (**) Option "fd" "56"
[   349.215] (II) event19 - Logitech Wireless Mouse: device removed
[   349.215] (**) Option "fd" "57"
[   349.215] (II) event11 - USB2.0 HD UVC WebCam: USB2.0 HD: device removed
[   349.215] (**) Option "fd" "58"
[   349.215] (II) event10 - ELAN1203:00 04F3:307A Mouse: device removed
[   349.215] (**) Option "fd" "59"
[   349.215] (II) event12 - ELAN1203:00 04F3:307A Touchpad: device removed
[   349.215] (**) Option "fd" "60"
[   349.215] (II) event9  - Asus WMI hotkeys: device removed
[   349.215] (**) Option "fd" "61"
[   349.215] (II) event3  - AT Translated Set 2 keyboard: device removed
[   349.215] (**) Option "fd" "55"
[   349.215] (II) event13 - Logitech Wireless Keyboard PID:4023: device removed
[   349.216] (II) UnloadModule: "libinput"
[   349.216] (II) systemd-logind: not releasing fd for 13:77, still in use
[   349.216] (II) UnloadModule: "libinput"
[   349.216] (II) systemd-logind: releasing fd for 13:67
[   349.318] (II) UnloadModule: "libinput"
[   349.318] (II) systemd-logind: releasing fd for 13:73
[   349.371] (II) UnloadModule: "libinput"
[   349.371] (II) systemd-logind: releasing fd for 13:76
[   349.432] (II) UnloadModule: "libinput"
[   349.432] (II) systemd-logind: releasing fd for 13:74
[   349.532] (II) UnloadModule: "libinput"
[   349.532] (II) systemd-logind: releasing fd for 13:75
[   349.585] (II) UnloadModule: "libinput"
[   349.585] (II) systemd-logind: releasing fd for 13:83
[   349.645] (II) UnloadModule: "libinput"
[   349.645] (II) systemd-logind: releasing fd for 13:77
[   349.662] (II) UnloadModule: "libinput"
[   349.662] (II) systemd-logind: releasing fd for 13:65
[   349.678] (II) UnloadModule: "libinput"
[   349.678] (II) systemd-logind: releasing fd for 13:64
[   349.695] (II) UnloadModule: "libinput"
[   349.695] (II) systemd-logind: releasing fd for 13:70
[   349.728] (II) UnloadModule: "libinput"
[   349.728] (II) systemd-logind: releasing fd for 13:69
[   349.762] (II) UnloadModule: "libinput"
[   349.762] (II) systemd-logind: releasing fd for 13:68
[   349.845] (II) NVIDIA(GPU-0): Deleting GPU-0
[   349.850] (WW) xf86CloseConsole: KDSETMODE failed: Input/output error
[   349.850] (WW) xf86CloseConsole: VT_GETMODE failed: Input/output error
[   350.013] (II) Server terminated successfully (0). Closing log file.

____________________________________________

*** /usr/share/X11/xorg.conf.d/10-amdgpu.conf
*** ls: -rw-r--r-- 1 root root 92 2022-02-24 07:53:07.000000000 -0300 /usr/share/X11/xorg.conf.d/10-amdgpu.conf
Section "OutputClass"
	Identifier "AMDgpu"
	MatchDriver "amdgpu"
	Driver "amdgpu"
EndSection
____________________________________________

*** /usr/share/X11/xorg.conf.d/10-nvidia-drm-outputclass.conf
*** ls: -rw-r--r-- 1 root root 227 2022-10-12 13:15:44.000000000 -0300 /usr/share/X11/xorg.conf.d/10-nvidia-drm-outputclass.conf
Section "OutputClass"
    Identifier "nvidia"
    MatchDriver "nvidia-drm"
    Driver "nvidia"
    Option "AllowEmptyInitialConfiguration"
    ModulePath "/usr/lib/nvidia/xorg"
    ModulePath "/usr/lib/xorg/modules"
EndSection

____________________________________________

*** /usr/share/X11/xorg.conf.d/10-quirks.conf
*** ls: -rw-r--r-- 1 root root 1350 2022-07-12 11:12:08.000000000 -0300 /usr/share/X11/xorg.conf.d/10-quirks.conf
# Collection of quirks and blacklist/whitelists for specific devices.


# Accelerometer device, posts data through ABS_X/ABS_Y, making X unusable
# http://bugs.freedesktop.org/show_bug.cgi?id=22442 
Section "InputClass"
        Identifier "ThinkPad HDAPS accelerometer blacklist"
        MatchProduct "ThinkPad HDAPS accelerometer data"
        Option "Ignore" "on"
EndSection

# https://bugzilla.redhat.com/show_bug.cgi?id=523914
# Mouse does not move in PV Xen guest
# Explicitly tell evdev to not ignore the absolute axes.
Section "InputClass"
        Identifier "Xen Virtual Pointer axis blacklist"
        MatchProduct "Xen Virtual Pointer"
        Option "IgnoreAbsoluteAxes" "off"
        Option "IgnoreRelativeAxes" "off"
EndSection

# https://bugs.freedesktop.org/show_bug.cgi?id=55867
# Bug 55867 - Doesn't know how to tag XI_TRACKBALL
Section "InputClass"
        Identifier "Tag trackballs as XI_TRACKBALL"
        MatchProduct "trackball"
        MatchDriver "evdev"
        Option "TypeName" "TRACKBALL"
EndSection

# https://bugs.freedesktop.org/show_bug.cgi?id=62831
# Bug 62831 - Mionix Naos 5000 mouse detected incorrectly
Section "InputClass"
        Identifier "Tag Mionix Naos 5000 mouse XI_MOUSE"
        MatchProduct "La-VIEW Technology Naos 5000 Mouse"
        MatchDriver "evdev"
        Option "TypeName" "MOUSE"
EndSection

____________________________________________

*** /usr/share/X11/xorg.conf.d/40-libinput.conf
*** ls: -rw-r--r-- 1 root root 1429 2022-01-24 03:44:53.000000000 -0300 /usr/share/X11/xorg.conf.d/40-libinput.conf
# Match on all types of devices but joysticks
#
# If you want to configure your devices, do not copy this file.
# Instead, use a config snippet that contains something like this:
#
# Section "InputClass"
#   Identifier "something or other"
#   MatchDriver "libinput"
#
#   MatchIsTouchpad "on"
#   ... other Match directives ...
#   Option "someoption" "value"
# EndSection
#
# This applies the option any libinput device also matched by the other
# directives. See the xorg.conf(5) man page for more info on
# matching devices.

Section "InputClass"
        Identifier "libinput pointer catchall"
        MatchIsPointer "on"
        MatchDevicePath "/dev/input/event*"
        Driver "libinput"
EndSection

Section "InputClass"
        Identifier "libinput keyboard catchall"
        MatchIsKeyboard "on"
        MatchDevicePath "/dev/input/event*"
        Driver "libinput"
EndSection

Section "InputClass"
        Identifier "libinput touchpad catchall"
        MatchIsTouchpad "on"
        MatchDevicePath "/dev/input/event*"
        Driver "libinput"
EndSection

Section "InputClass"
        Identifier "libinput touchscreen catchall"
        MatchIsTouchscreen "on"
        MatchDevicePath "/dev/input/event*"
        Driver "libinput"
EndSection

Section "InputClass"
        Identifier "libinput tablet catchall"
        MatchIsTablet "on"
        MatchDevicePath "/dev/input/event*"
        Driver "libinput"
EndSection

____________________________________________

*** /var/log/Xorg.0.log.old
*** ls: -rw-r--r-- 1 root gdm 58095 2022-10-17 07:29:59.395329110 -0300 /var/log/Xorg.0.log.old
[     4.531] (--) Log file renamed from "/var/log/Xorg.pid-872.log" to "/var/log/Xorg.0.log"
[     4.532] 
X.Org X Server 1.21.1.4
X Protocol Version 11, Revision 0
[     4.532] Current Operating System: Linux nomade007 6.0.1-arch2-1 #1 SMP PREEMPT_DYNAMIC Thu, 13 Oct 2022 18:58:49 +0000 x86_64
[     4.532] Kernel command line: initrd=\amd-ucode.img initrd=\initramfs-linux.img root=PARTUUID=f407dfcd-5b75-c540-99c7-811fac3135b7 rw
[     4.532]  
[     4.532] Current version of pixman: 0.40.0
[     4.532] 	Before reporting problems, check http://wiki.x.org
	to make sure that you have the latest version.
[     4.532] Markers: (--) probed, (**) from config file, (==) default setting,
	(++) from command line, (!!) notice, (II) informational,
	(WW) warning, (EE) error, (NI) not implemented, (??) unknown.
[     4.532] (==) Log file: "/var/log/Xorg.0.log", Time: Mon Oct 17 07:29:48 2022
[     4.533] (==) Using system config directory "/usr/share/X11/xorg.conf.d"
[     4.534] (==) No Layout section.  Using the first Screen section.
[     4.534] (==) No screen section available. Using defaults.
[     4.534] (**) |-->Screen "Default Screen Section" (0)
[     4.534] (**) |   |-->Monitor "<default monitor>"
[     4.534] (==) No monitor specified for screen "Default Screen Section".
	Using a default monitor configuration.
[     4.534] (==) Automatically adding devices
[     4.534] (==) Automatically enabling devices
[     4.534] (==) Automatically adding GPU devices
[     4.534] (==) Automatically binding GPU devices
[     4.534] (==) Max clients allowed: 256, resource mask: 0x1fffff
[     4.534] (WW) The directory "/usr/share/fonts/misc" does not exist.
[     4.534] 	Entry deleted from font path.
[     4.535] (WW) The directory "/usr/share/fonts/OTF" does not exist.
[     4.535] 	Entry deleted from font path.
[     4.535] (WW) The directory "/usr/share/fonts/Type1" does not exist.
[     4.535] 	Entry deleted from font path.
[     4.535] (==) FontPath set to:
	/usr/share/fonts/TTF,
	/usr/share/fonts/100dpi,
	/usr/share/fonts/75dpi
[     4.535] (==) ModulePath set to "/usr/lib/xorg/modules"
[     4.535] (II) The server relies on udev to provide the list of input devices.
	If no devices become available, reconfigure udev or disable AutoAddDevices.
[     4.535] (II) Module ABI versions:
[     4.535] 	X.Org ANSI C Emulation: 0.4
[     4.535] 	X.Org Video Driver: 25.2
[     4.535] 	X.Org XInput driver : 24.4
[     4.535] 	X.Org Server Extension : 10.0
[     4.536] (++) using VT number 1

[     4.536] (II) systemd-logind: took control of session /org/freedesktop/login1/session/_31
[     4.537] (II) xfree86: Adding drm device (/dev/dri/card1)
[     4.537] (II) Platform probe for /sys/devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm/card1
[     4.537] (II) systemd-logind: got fd for /dev/dri/card1 226:1 fd 14 paused 0
[     4.537] (II) xfree86: Adding drm device (/dev/dri/card0)
[     4.537] (II) Platform probe for /sys/devices/pci0000:00/0000:00:08.1/0000:06:00.0/drm/card0
[     4.538] (II) systemd-logind: got fd for /dev/dri/card0 226:0 fd 15 paused 0
[     4.539] (**) OutputClass "nvidia" ModulePath extended to "/usr/lib/nvidia/xorg,/usr/lib/xorg/modules,/usr/lib/xorg/modules"
[     4.955] (--) PCI: (1@0:0:0) 10de:2520:1043:16a2 rev 161, Mem @ 0xfb000000/16777216, 0xfc00000000/8589934592, 0xfe00000000/33554432, I/O @ 0x0000f000/128, BIOS @ 0x????????/524288
[     4.955] (--) PCI:*(6@0:0:0) 1002:1638:1043:16a2 rev 197, Mem @ 0xfe10000000/268435456, 0xfe20000000/2097152, 0xfc500000/524288, I/O @ 0x0000d000/256
[     4.955] (WW) Open ACPI failed (/var/run/acpid.socket) (No such file or directory)
[     4.955] (II) LoadModule: "glx"
[     4.957] (II) Loading /usr/lib/xorg/modules/extensions/libglx.so
[     4.960] (II) Module glx: vendor="X.Org Foundation"
[     4.960] 	compiled for 1.21.1.4, module version = 1.0.0
[     4.960] 	ABI class: X.Org Server Extension, version 10.0
[     4.960] (II) Applying OutputClass "AMDgpu" to /dev/dri/card0
[     4.960] 	loading driver: amdgpu
[     4.960] (II) Applying OutputClass "nvidia" to /dev/dri/card1
[     4.960] 	loading driver: nvidia
[     4.960] (==) Matched amdgpu as autoconfigured driver 0
[     4.960] (==) Matched ati as autoconfigured driver 1
[     4.960] (==) Matched nvidia as autoconfigured driver 2
[     4.960] (==) Matched nouveau as autoconfigured driver 3
[     4.960] (==) Matched nv as autoconfigured driver 4
[     4.960] (==) Matched modesetting as autoconfigured driver 5
[     4.960] (==) Matched fbdev as autoconfigured driver 6
[     4.960] (==) Matched vesa as autoconfigured driver 7
[     4.960] (==) Assigned the driver to the xf86ConfigLayout
[     4.960] (II) LoadModule: "amdgpu"
[     4.961] (II) Loading /usr/lib/xorg/modules/drivers/amdgpu_drv.so
[     4.962] (II) Module amdgpu: vendor="X.Org Foundation"
[     4.962] 	compiled for 1.21.1.3, module version = 22.0.0
[     4.962] 	Module class: X.Org Video Driver
[     4.962] 	ABI class: X.Org Video Driver, version 25.2
[     4.962] (II) LoadModule: "ati"
[     4.962] (WW) Warning, couldn't open module ati
[     4.962] (EE) Failed to load module "ati" (module does not exist, 0)
[     4.962] (II) LoadModule: "nvidia"
[     4.962] (II) Loading /usr/lib/xorg/modules/drivers/nvidia_drv.so
[     4.964] (II) Module nvidia: vendor="NVIDIA Corporation"
[     4.964] 	compiled for 1.6.99.901, module version = 1.0.0
[     4.964] 	Module class: X.Org Video Driver
[     4.964] (II) LoadModule: "nouveau"
[     4.964] (WW) Warning, couldn't open module nouveau
[     4.964] (EE) Failed to load module "nouveau" (module does not exist, 0)
[     4.964] (II) LoadModule: "nv"
[     4.964] (WW) Warning, couldn't open module nv
[     4.964] (EE) Failed to load module "nv" (module does not exist, 0)
[     4.964] (II) LoadModule: "modesetting"
[     4.965] (II) Loading /usr/lib/xorg/modules/drivers/modesetting_drv.so
[     4.965] (II) Module modesetting: vendor="X.Org Foundation"
[     4.965] 	compiled for 1.21.1.4, module version = 1.21.1
[     4.965] 	Module class: X.Org Video Driver
[     4.965] 	ABI class: X.Org Video Driver, version 25.2
[     4.965] (II) LoadModule: "fbdev"
[     4.965] (II) Loading /usr/lib/xorg/modules/drivers/fbdev_drv.so
[     4.965] (II) Module fbdev: vendor="X.Org Foundation"
[     4.965] 	compiled for 1.21.1.1, module version = 0.5.0
[     4.965] 	Module class: X.Org Video Driver
[     4.965] 	ABI class: X.Org Video Driver, version 25.2
[     4.965] (II) LoadModule: "vesa"
[     4.965] (II) Loading /usr/lib/xorg/modules/drivers/vesa_drv.so
[     4.965] (II) Module vesa: vendor="X.Org Foundation"
[     4.965] 	compiled for 1.21.1.3, module version = 2.5.0
[     4.965] 	Module class: X.Org Video Driver
[     4.965] 	ABI class: X.Org Video Driver, version 25.2
[     4.965] (II) AMDGPU: Driver for AMD Radeon:
	All GPUs supported by the amdgpu kernel driver
[     4.965] (II) NVIDIA dlloader X Driver  520.56.06  Thu Oct  6 21:29:26 UTC 2022
[     4.965] (II) NVIDIA Unified Driver for all Supported NVIDIA GPUs
[     4.966] (II) modesetting: Driver for Modesetting Kernel Drivers: kms
[     4.966] (II) FBDEV: driver for framebuffer: fbdev
[     4.966] (II) VESA: driver for VESA chipsets: vesa
[     4.970] (WW) Falling back to old probe method for modesetting
[     4.970] (WW) Falling back to old probe method for fbdev
[     4.970] (II) Loading sub module "fbdevhw"
[     4.970] (II) LoadModule: "fbdevhw"
[     4.970] (II) Loading /usr/lib/xorg/modules/libfbdevhw.so
[     4.971] (II) Module fbdevhw: vendor="X.Org Foundation"
[     4.971] 	compiled for 1.21.1.4, module version = 0.0.2
[     4.971] 	ABI class: X.Org Video Driver, version 25.2
[     4.971] (II) systemd-logind: releasing fd for 226:1
[     4.971] (II) Loading sub module "fb"
[     4.971] (II) LoadModule: "fb"
[     4.971] (II) Module "fb" already built-in
[     4.971] (II) Loading sub module "wfb"
[     4.971] (II) LoadModule: "wfb"
[     4.971] (II) Loading /usr/lib/xorg/modules/libwfb.so
[     4.972] (II) Module wfb: vendor="X.Org Foundation"
[     4.972] 	compiled for 1.21.1.4, module version = 1.0.0
[     4.972] 	ABI class: X.Org ANSI C Emulation, version 0.4
[     4.972] (II) Loading sub module "ramdac"
[     4.972] (II) LoadModule: "ramdac"
[     4.972] (II) Module "ramdac" already built-in
[     4.972] (II) AMDGPU(0): Creating default Display subsection in Screen section
	"Default Screen Section" for depth/fbbpp 24/32
[     4.972] (==) AMDGPU(0): Depth 24, (--) framebuffer bpp 32
[     4.972] (II) AMDGPU(0): Pixel depth = 24 bits stored in 4 bytes (32 bpp pixmaps)
[     4.972] (==) AMDGPU(0): Default visual is TrueColor
[     4.972] (==) AMDGPU(0): RGB weight 888
[     4.972] (II) AMDGPU(0): Using 8 bits per RGB (8 bit DAC)
[     4.972] (--) AMDGPU(0): Chipset: "Unknown AMD Radeon GPU" (ChipID = 0x1638)
[     4.972] (II) Loading sub module "fb"
[     4.972] (II) LoadModule: "fb"
[     4.972] (II) Module "fb" already built-in
[     4.972] (II) Loading sub module "dri2"
[     4.972] (II) LoadModule: "dri2"
[     4.972] (II) Module "dri2" already built-in
[     5.070] (II) Loading sub module "glamoregl"
[     5.070] (II) LoadModule: "glamoregl"
[     5.070] (II) Loading /usr/lib/xorg/modules/libglamoregl.so
[     5.074] (II) Module glamoregl: vendor="X.Org Foundation"
[     5.074] 	compiled for 1.21.1.4, module version = 1.0.1
[     5.074] 	ABI class: X.Org ANSI C Emulation, version 0.4
[     6.550] (II) AMDGPU(0): glamor X acceleration enabled on RENOIR (renoir, LLVM 14.0.6, DRM 3.48, 6.0.1-arch2-1)
[     6.550] (II) AMDGPU(0): glamor detected, initialising EGL layer.
[     6.550] (==) AMDGPU(0): TearFree property default: auto
[     6.550] (==) AMDGPU(0): VariableRefresh: disabled
[     6.550] (==) AMDGPU(0): AsyncFlipSecondaries: disabled
[     6.550] (II) AMDGPU(0): KMS Pageflipping: enabled
[     6.552] (II) AMDGPU(0): Output eDP has no monitor section
[     6.553] (II) AMDGPU(0): Output HDMI-A-0 has no monitor section
[     6.560] (II) AMDGPU(0): EDID for output eDP
[     6.560] (II) AMDGPU(0): Manufacturer: NCP  Model: 4d  Serial#: 0
[     6.560] (II) AMDGPU(0): Year: 2019  Week: 51
[     6.560] (II) AMDGPU(0): EDID Version: 1.4
[     6.560] (II) AMDGPU(0): Digital Display Input
[     6.560] (II) AMDGPU(0): 8 bits per channel
[     6.560] (II) AMDGPU(0): Digital interface is DisplayPort
[     6.560] (II) AMDGPU(0): Max Image Size [cm]: horiz.: 34  vert.: 19
[     6.560] (II) AMDGPU(0): Gamma: 2.20
[     6.560] (II) AMDGPU(0): No DPMS capabilities specified
[     6.560] (II) AMDGPU(0): Supported color encodings: RGB 4:4:4 
[     6.560] (II) AMDGPU(0): First detailed timing is preferred mode
[     6.560] (II) AMDGPU(0): Preferred mode is native pixel format and refresh rate
[     6.560] (II) AMDGPU(0): Display is continuous-frequency
[     6.560] (II) AMDGPU(0): redX: 0.595 redY: 0.361   greenX: 0.346 greenY: 0.555
[     6.560] (II) AMDGPU(0): blueX: 0.157 blueY: 0.106   whiteX: 0.312 whiteY: 0.328
[     6.560] (II) AMDGPU(0): Manufacturer's mask: 0
[     6.560] (II) AMDGPU(0): Supported detailed timing:
[     6.560] (II) AMDGPU(0): clock: 354.7 MHz   Image Size:  344 x 194 mm
[     6.560] (II) AMDGPU(0): h_active: 1920  h_sync: 1968  h_sync_end 2000 h_blank_end 2180 h_border: 0
[     6.560] (II) AMDGPU(0): v_active: 1080  v_sync: 1083  v_sync_end 1088 v_blanking: 1130 v_border: 0
[     6.560] (II) AMDGPU(0): Supported detailed timing:
[     6.560] (II) AMDGPU(0): clock: 147.8 MHz   Image Size:  344 x 194 mm
[     6.560] (II) AMDGPU(0): h_active: 1920  h_sync: 1968  h_sync_end 2000 h_blank_end 2180 h_border: 0
[     6.560] (II) AMDGPU(0): v_active: 1080  v_sync: 1083  v_sync_end 1088 v_blanking: 1130 v_border: 0
[     6.560] (II) AMDGPU(0): Ranges: V min: 48 V max: 144 Hz, H min: 163 H max: 163 kHz, PixClock max 355 MHz
[     6.560] (II) AMDGPU(0):  LM156LF-2F03
[     6.560] (II) AMDGPU(0): EDID (in hex):
[     6.560] (II) AMDGPU(0): 	00ffffffffffff0038704d0000000000
[     6.560] (II) AMDGPU(0): 	331d0104a5221378036850985c588e28
[     6.560] (II) AMDGPU(0): 	1b505400000001010101010101010101
[     6.560] (II) AMDGPU(0): 	010101010101918a8004713832403020
[     6.560] (II) AMDGPU(0): 	350058c21000001abd39800471383240
[     6.560] (II) AMDGPU(0): 	3020350058c21000001a000000fd0030
[     6.560] (II) AMDGPU(0): 	90a3a323010a202020202020000000fe
[     6.560] (II) AMDGPU(0): 	004c4d3135364c462d324630330a0035
[     6.560] (II) AMDGPU(0): Printing probed modes for output eDP
[     6.560] (II) AMDGPU(0): Modeline "1920x1080"x144.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[     6.560] (II) AMDGPU(0): Modeline "1920x1080"x120.0  354.73  1920 1968 2000 2180  1080 1309 1314 1356 +hsync -vsync (162.7 kHz e)
[     6.560] (II) AMDGPU(0): Modeline "1920x1080"x96.0  354.73  1920 1968 2000 2180  1080 1648 1653 1695 +hsync -vsync (162.7 kHz e)
[     6.560] (II) AMDGPU(0): Modeline "1920x1080"x72.0  354.73  1920 1968 2000 2180  1080 2213 2218 2260 +hsync -vsync (162.7 kHz e)
[     6.560] (II) AMDGPU(0): Modeline "1920x1080"x60.0  354.73  1920 1968 2000 2180  1080 2665 2670 2712 +hsync -vsync (162.7 kHz e)
[     6.560] (II) AMDGPU(0): Modeline "1920x1080"x50.0  354.73  1920 1968 2000 2180  1080 3207 3212 3254 +hsync -vsync (162.7 kHz e)
[     6.560] (II) AMDGPU(0): Modeline "1920x1080"x48.0  354.73  1920 1968 2000 2180  1080 3343 3348 3390 +hsync -vsync (162.7 kHz e)
[     6.560] (II) AMDGPU(0): Modeline "1920x1080"x60.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[     6.560] (II) AMDGPU(0): Modeline "1680x1050"x144.0  354.73  1680 1968 2000 2180  1050 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[     6.560] (II) AMDGPU(0): Modeline "1280x1024"x144.0  354.73  1280 1968 2000 2180  1024 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[     6.560] (II) AMDGPU(0): Modeline "1440x900"x144.0  354.73  1440 1968 2000 2180  900 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[     6.560] (II) AMDGPU(0): Modeline "1280x800"x144.0  354.73  1280 1968 2000 2180  800 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[     6.560] (II) AMDGPU(0): Modeline "1280x720"x144.0  354.73  1280 1968 2000 2180  720 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[     6.560] (II) AMDGPU(0): Modeline "1024x768"x144.0  354.73  1024 1968 2000 2180  768 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[     6.560] (II) AMDGPU(0): Modeline "800x600"x144.0  354.73  800 1968 2000 2180  600 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[     6.560] (II) AMDGPU(0): Modeline "640x480"x144.0  354.73  640 1968 2000 2180  480 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[     6.562] (II) AMDGPU(0): EDID for output HDMI-A-0
[     6.562] (II) AMDGPU(0): Manufacturer: SAM  Model: c4e  Serial#: 1113216587
[     6.562] (II) AMDGPU(0): Year: 2020  Week: 41
[     6.562] (II) AMDGPU(0): EDID Version: 1.3
[     6.562] (II) AMDGPU(0): Digital Display Input
[     6.562] (II) AMDGPU(0): Max Image Size [cm]: horiz.: 61  vert.: 35
[     6.562] (II) AMDGPU(0): Gamma: 2.20
[     6.562] (II) AMDGPU(0): DPMS capabilities: Off
[     6.562] (II) AMDGPU(0): Supported color encodings: RGB 4:4:4 YCrCb 4:4:4 
[     6.562] (II) AMDGPU(0): First detailed timing is preferred mode
[     6.562] (II) AMDGPU(0): redX: 0.634 redY: 0.341   greenX: 0.312 greenY: 0.636
[     6.562] (II) AMDGPU(0): blueX: 0.158 blueY: 0.062   whiteX: 0.312 whiteY: 0.329
[     6.562] (II) AMDGPU(0): Supported established timings:
[     6.562] (II) AMDGPU(0): 720x400@70Hz
[     6.562] (II) AMDGPU(0): 640x480@60Hz
[     6.562] (II) AMDGPU(0): 640x480@67Hz
[     6.562] (II) AMDGPU(0): 640x480@72Hz
[     6.562] (II) AMDGPU(0): 640x480@75Hz
[     6.562] (II) AMDGPU(0): 800x600@56Hz
[     6.562] (II) AMDGPU(0): 800x600@60Hz
[     6.562] (II) AMDGPU(0): 800x600@72Hz
[     6.562] (II) AMDGPU(0): 800x600@75Hz
[     6.562] (II) AMDGPU(0): 832x624@75Hz
[     6.562] (II) AMDGPU(0): 1024x768@60Hz
[     6.562] (II) AMDGPU(0): 1024x768@70Hz
[     6.562] (II) AMDGPU(0): 1024x768@75Hz
[     6.562] (II) AMDGPU(0): 1280x1024@75Hz
[     6.562] (II) AMDGPU(0): 1152x864@75Hz
[     6.562] (II) AMDGPU(0): Manufacturer's mask: 0
[     6.562] (II) AMDGPU(0): Supported standard timings:
[     6.562] (II) AMDGPU(0): #0: hsize: 1152  vsize 864  refresh: 75  vid: 20337
[     6.562] (II) AMDGPU(0): #1: hsize: 1280  vsize 800  refresh: 60  vid: 129
[     6.562] (II) AMDGPU(0): #2: hsize: 1280  vsize 720  refresh: 60  vid: 49281
[     6.562] (II) AMDGPU(0): #3: hsize: 1280  vsize 1024  refresh: 60  vid: 32897
[     6.562] (II) AMDGPU(0): #4: hsize: 1440  vsize 900  refresh: 60  vid: 149
[     6.562] (II) AMDGPU(0): #5: hsize: 1600  vsize 900  refresh: 60  vid: 49321
[     6.562] (II) AMDGPU(0): #6: hsize: 1680  vsize 1050  refresh: 60  vid: 179
[     6.562] (II) AMDGPU(0): Supported detailed timing:
[     6.562] (II) AMDGPU(0): clock: 297.0 MHz   Image Size:  608 x 345 mm
[     6.562] (II) AMDGPU(0): h_active: 3840  h_sync: 4016  h_sync_end 4104 h_blank_end 4400 h_border: 0
[     6.562] (II) AMDGPU(0): v_active: 2160  v_sync: 2168  v_sync_end 2178 v_blanking: 2250 v_border: 0
[     6.562] (II) AMDGPU(0): Ranges: V min: 24 V max: 75 Hz, H min: 30 H max: 90 kHz, PixClock max 305 MHz
[     6.562] (II) AMDGPU(0): Monitor name: U28E590
[     6.562] (II) AMDGPU(0): Serial No: H4ZNA00044
[     6.562] (II) AMDGPU(0): Supported detailed timing:
[     6.562] (II) AMDGPU(0): clock: 148.5 MHz   Image Size:  608 x 345 mm
[     6.562] (II) AMDGPU(0): h_active: 1920  h_sync: 2008  h_sync_end 2052 h_blank_end 2200 h_border: 0
[     6.562] (II) AMDGPU(0): v_active: 1080  v_sync: 1084  v_sync_end 1089 v_blanking: 1125 v_border: 0
[     6.562] (II) AMDGPU(0): Supported detailed timing:
[     6.562] (II) AMDGPU(0): clock: 148.5 MHz   Image Size:  608 x 345 mm
[     6.562] (II) AMDGPU(0): h_active: 1920  h_sync: 2448  h_sync_end 2492 h_blank_end 2640 h_border: 0
[     6.562] (II) AMDGPU(0): v_active: 1080  v_sync: 1084  v_sync_end 1089 v_blanking: 1125 v_border: 0
[     6.562] (II) AMDGPU(0): Supported detailed timing:
[     6.562] (II) AMDGPU(0): clock: 74.2 MHz   Image Size:  608 x 345 mm
[     6.562] (II) AMDGPU(0): h_active: 1280  h_sync: 1390  h_sync_end 1430 h_blank_end 1650 h_border: 0
[     6.562] (II) AMDGPU(0): v_active: 720  v_sync: 725  v_sync_end 730 v_blanking: 750 v_border: 0
[     6.562] (II) AMDGPU(0): Supported detailed timing:
[     6.562] (II) AMDGPU(0): clock: 241.5 MHz   Image Size:  608 x 345 mm
[     6.562] (II) AMDGPU(0): h_active: 2560  h_sync: 2608  h_sync_end 2640 h_blank_end 2720 h_border: 0
[     6.562] (II) AMDGPU(0): v_active: 1440  v_sync: 1443  v_sync_end 1448 v_blanking: 1481 v_border: 0
[     6.562] (II) AMDGPU(0): Number of EDID sections to follow: 1
[     6.562] (II) AMDGPU(0): EDID (in hex):
[     6.562] (II) AMDGPU(0): 	00ffffffffffff004c2d4e0c4b565a42
[     6.562] (II) AMDGPU(0): 	291e0103803d23782a5fb1a2574fa228
[     6.562] (II) AMDGPU(0): 	0f5054bfef80714f810081c081809500
[     6.562] (II) AMDGPU(0): 	a9c0b300010104740030f2705a80b058
[     6.562] (II) AMDGPU(0): 	8a0060592100001e000000fd00184b1e
[     6.562] (II) AMDGPU(0): 	5a1e000a202020202020000000fc0055
[     6.562] (II) AMDGPU(0): 	3238453539300a2020202020000000ff
[     6.562] (II) AMDGPU(0): 	0048345a4e4130303034340a202001d3
[     6.562] (II) AMDGPU(0): 	020324f0495f10041f13031220222309
[     6.562] (II) AMDGPU(0): 	0707830100006d030c001000803c2010
[     6.562] (II) AMDGPU(0): 	60010203023a801871382d40582c4500
[     6.562] (II) AMDGPU(0): 	60592100001e023a80d072382d40102c
[     6.562] (II) AMDGPU(0): 	458060592100001e011d007251d01e20
[     6.562] (II) AMDGPU(0): 	6e28550060592100001e565e00a0a0a0
[     6.562] (II) AMDGPU(0): 	29503020350060592100001a00000000
[     6.562] (II) AMDGPU(0): 	00000000000000000000000000000067
[     6.562] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[     6.562] (II) AMDGPU(0): Printing probed modes for output HDMI-A-0
[     6.562] (II) AMDGPU(0): Modeline "3840x2160"x30.0  297.00  3840 4016 4104 4400  2160 2168 2178 2250 +hsync +vsync (67.5 kHz eP)
[     6.562] (II) AMDGPU(0): Modeline "3840x2160"x25.0  297.00  3840 4896 4984 5280  2160 2168 2178 2250 +hsync +vsync (56.2 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "3840x2160"x24.0  297.00  3840 5116 5204 5500  2160 2168 2178 2250 +hsync +vsync (54.0 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "3840x2160"x30.0  296.70  3840 4016 4104 4400  2160 2168 2178 2250 +hsync +vsync (67.4 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "3840x2160"x24.0  296.70  3840 5116 5204 5500  2160 2168 2178 2250 +hsync +vsync (53.9 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "2560x1440"x60.0  241.50  2560 2608 2640 2720  1440 1443 1448 1481 +hsync -vsync (88.8 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1920x1200"x30.0  297.00  1920 4016 4104 4400  1200 2168 2178 2250 +hsync +vsync (67.5 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1920x1080"x60.0  148.50  1920 2008 2052 2200  1080 1084 1089 1125 +hsync +vsync (67.5 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1920x1080"x50.0  148.50  1920 2448 2492 2640  1080 1084 1089 1125 +hsync +vsync (56.2 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1920x1080"x59.9  148.35  1920 2008 2052 2200  1080 1084 1089 1125 +hsync +vsync (67.4 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1920x1080"x30.0   74.25  1920 2008 2052 2200  1080 1084 1089 1125 +hsync +vsync (33.8 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1920x1080"x24.0   74.25  1920 2558 2602 2750  1080 1084 1089 1125 +hsync +vsync (27.0 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1920x1080"x30.0   74.18  1920 2008 2052 2200  1080 1084 1089 1125 +hsync +vsync (33.7 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1920x1080"x24.0   74.18  1920 2558 2602 2750  1080 1084 1089 1125 +hsync +vsync (27.0 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1600x1200"x30.0  297.00  1600 4016 4104 4400  1200 2168 2178 2250 +hsync +vsync (67.5 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1680x1050"x59.9  119.00  1680 1728 1760 1840  1050 1053 1059 1080 +hsync -vsync (64.7 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1600x900"x60.0  108.00  1600 1624 1704 1800  900 901 904 1000 +hsync +vsync (60.0 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1280x1024"x75.0  135.00  1280 1296 1440 1688  1024 1025 1028 1066 +hsync +vsync (80.0 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1280x1024"x60.0  108.00  1280 1328 1440 1688  1024 1025 1028 1066 +hsync +vsync (64.0 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1440x900"x59.9   88.75  1440 1488 1520 1600  900 903 909 926 +hsync -vsync (55.5 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1280x800"x59.9   71.00  1280 1328 1360 1440  800 803 809 823 +hsync -vsync (49.3 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1152x864"x75.0  108.00  1152 1216 1344 1600  864 865 868 900 +hsync +vsync (67.5 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1280x720"x60.0   74.25  1280 1390 1430 1650  720 725 730 750 +hsync +vsync (45.0 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1280x720"x50.0   74.25  1280 1720 1760 1980  720 725 730 750 +hsync +vsync (37.5 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1280x720"x59.9   74.18  1280 1390 1430 1650  720 725 730 750 +hsync +vsync (45.0 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1024x768"x75.0   78.75  1024 1040 1136 1312  768 769 772 800 +hsync +vsync (60.0 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1024x768"x70.1   75.00  1024 1048 1184 1328  768 771 777 806 -hsync -vsync (56.5 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "1024x768"x60.0   65.00  1024 1048 1184 1344  768 771 777 806 -hsync -vsync (48.4 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "832x624"x74.6   57.28  832 864 928 1152  624 625 628 667 -hsync -vsync (49.7 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "800x600"x72.2   50.00  800 856 976 1040  600 637 643 666 +hsync +vsync (48.1 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "800x600"x75.0   49.50  800 816 896 1056  600 601 604 625 +hsync +vsync (46.9 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "800x600"x60.3   40.00  800 840 968 1056  600 601 605 628 +hsync +vsync (37.9 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "800x600"x56.2   36.00  800 824 896 1024  600 601 603 625 +hsync +vsync (35.2 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "720x576"x50.0   27.00  720 732 796 864  576 581 586 625 -hsync -vsync (31.2 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "720x480"x60.0   27.03  720 736 798 858  480 489 495 525 -hsync -vsync (31.5 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "720x480"x59.9   27.00  720 736 798 858  480 489 495 525 -hsync -vsync (31.5 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "640x480"x75.0   31.50  640 656 720 840  480 481 484 500 -hsync -vsync (37.5 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "640x480"x72.8   31.50  640 664 704 832  480 489 492 520 -hsync -vsync (37.9 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "640x480"x66.7   30.24  640 704 768 864  480 483 486 525 -hsync -vsync (35.0 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "640x480"x60.0   25.20  640 656 752 800  480 490 492 525 -hsync -vsync (31.5 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "640x480"x59.9   25.18  640 656 752 800  480 490 492 525 -hsync -vsync (31.5 kHz e)
[     6.562] (II) AMDGPU(0): Modeline "720x400"x70.1   28.32  720 738 846 900  400 412 414 449 -hsync +vsync (31.5 kHz e)
[     6.562] (II) AMDGPU(0): Output eDP connected
[     6.562] (II) AMDGPU(0): Output HDMI-A-0 connected
[     6.562] (II) AMDGPU(0): Using spanning desktop for initial modes
[     6.562] (II) AMDGPU(0): Output eDP using initial mode 1920x1080 +0+0
[     6.562] (II) AMDGPU(0): Output HDMI-A-0 using initial mode 3840x2160 +1920+0
[     6.562] (II) AMDGPU(0): mem size init: gart size :7c641d000 vram size: s:1c771000 visible:1c771000
[     6.562] (==) AMDGPU(0): DPI set to (96, 96)
[     6.562] (==) AMDGPU(0): Using gamma correction (1.0, 1.0, 1.0)
[     6.562] (II) Loading sub module "ramdac"
[     6.562] (II) LoadModule: "ramdac"
[     6.562] (II) Module "ramdac" already built-in
[     6.562] (==) NVIDIA(G0): Depth 24, (==) framebuffer bpp 32
[     6.562] (==) NVIDIA(G0): RGB weight 888
[     6.562] (==) NVIDIA(G0): Default visual is TrueColor
[     6.562] (==) NVIDIA(G0): Using gamma correction (1.0, 1.0, 1.0)
[     6.562] (II) Applying OutputClass "nvidia" options to /dev/dri/card1
[     6.563] (**) NVIDIA(G0): Option "AllowEmptyInitialConfiguration"
[     6.563] (**) NVIDIA(G0): Enabling 2D acceleration
[     6.563] (II) Loading sub module "glxserver_nvidia"
[     6.563] (II) LoadModule: "glxserver_nvidia"
[     6.563] (II) Loading /usr/lib/nvidia/xorg/libglxserver_nvidia.so
[     6.578] (II) Module glxserver_nvidia: vendor="NVIDIA Corporation"
[     6.578] 	compiled for 1.6.99.901, module version = 1.0.0
[     6.578] 	Module class: X.Org Server Extension
[     6.578] (II) NVIDIA GLX Module  520.56.06  Thu Oct  6 21:26:26 UTC 2022
[     6.578] (II) NVIDIA: The X server supports PRIME Render Offload.
[     6.595] (--) NVIDIA(0): Valid display device(s) on GPU-0 at PCI:1:0:0
[     6.595] (--) NVIDIA(0):     DFP-0
[     6.595] (--) NVIDIA(0):     DFP-1
[     6.596] (II) NVIDIA(G0): NVIDIA GPU NVIDIA GeForce RTX 3060 Laptop GPU (GA106-A) at
[     6.596] (II) NVIDIA(G0):     PCI:1:0:0 (GPU-0)
[     6.596] (--) NVIDIA(G0): Memory: 6291456 kBytes
[     6.596] (--) NVIDIA(G0): VideoBIOS: 94.06.17.00.5f
[     6.596] (II) NVIDIA(G0): Detected PCI Express Link width: 16X
[     6.596] (--) NVIDIA(GPU-0): DFP-0: disconnected
[     6.596] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[     6.596] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[     6.596] (--) NVIDIA(GPU-0): 
[     6.596] (--) NVIDIA(GPU-0): DFP-1: disconnected
[     6.596] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[     6.596] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[     6.596] (--) NVIDIA(GPU-0): 
[     6.597] (II) NVIDIA(G0): Validated MetaModes:
[     6.597] (II) NVIDIA(G0):     "NULL"
[     6.597] (II) NVIDIA(G0): Virtual screen size determined to be 640 x 480
[     6.597] (WW) NVIDIA(G0): Unable to get display device for DPI computation.
[     6.597] (==) NVIDIA(G0): DPI set to (75, 75); computed from built-in default
[     6.597] (II) UnloadModule: "modesetting"
[     6.597] (II) Unloading modesetting
[     6.597] (II) UnloadModule: "fbdev"
[     6.597] (II) Unloading fbdev
[     6.597] (II) UnloadSubModule: "fbdevhw"
[     6.597] (II) Unloading fbdevhw
[     6.597] (II) UnloadModule: "vesa"
[     6.597] (II) Unloading vesa
[     6.597] (II) AMDGPU(0): [DRI2] Setup complete
[     6.597] (II) AMDGPU(0): [DRI2]   DRI driver: radeonsi
[     6.597] (II) AMDGPU(0): [DRI2]   VDPAU driver: radeonsi
[     6.635] (II) AMDGPU(0): Front buffer pitch: 23040 bytes
[     6.635] (II) AMDGPU(0): SYNC extension fences enabled
[     6.635] (II) AMDGPU(0): Present extension enabled
[     6.635] (==) AMDGPU(0): DRI3 enabled
[     6.635] (==) AMDGPU(0): Backing store enabled
[     6.635] (II) AMDGPU(0): Direct rendering enabled
[     6.652] (II) AMDGPU(0): Use GLAMOR acceleration.
[     6.652] (II) AMDGPU(0): Acceleration enabled
[     6.652] (==) AMDGPU(0): DPMS enabled
[     6.652] (==) AMDGPU(0): Silken mouse enabled
[     6.652] (II) AMDGPU(0): Set up textured video (glamor)
[     6.692] (II) NVIDIA: Reserving 24576.00 MB of virtual memory for indirect memory
[     6.692] (II) NVIDIA:     access.
[     6.701] (II) NVIDIA(G0): ACPI: failed to connect to the ACPI event daemon; the daemon
[     6.701] (II) NVIDIA(G0):     may not be running or the "AcpidSocketPath" X
[     6.701] (II) NVIDIA(G0):     configuration option may not be set correctly.  When the
[     6.701] (II) NVIDIA(G0):     ACPI event daemon is available, the NVIDIA X driver will
[     6.701] (II) NVIDIA(G0):     try to use it to receive ACPI event notifications.  For
[     6.701] (II) NVIDIA(G0):     details, please see the "ConnectToAcpid" and
[     6.701] (II) NVIDIA(G0):     "AcpidSocketPath" X configuration options in Appendix B: X
[     6.701] (II) NVIDIA(G0):     Config Options in the README.
[     6.714] (II) NVIDIA(G0): Setting mode "NULL"
[     6.722] (==) NVIDIA(G0): Disabling shared memory pixmaps
[     6.722] (==) NVIDIA(G0): Backing store enabled
[     6.722] (==) NVIDIA(G0): Silken mouse enabled
[     6.722] (==) NVIDIA(G0): DPMS enabled
[     6.722] (II) Loading sub module "dri2"
[     6.722] (II) LoadModule: "dri2"
[     6.722] (II) Module "dri2" already built-in
[     6.722] (II) NVIDIA(G0): [DRI2] Setup complete
[     6.722] (II) NVIDIA(G0): [DRI2]   VDPAU driver: nvidia
[     6.722] (II) Initializing extension Generic Event Extension
[     6.722] (II) Initializing extension SHAPE
[     6.722] (II) Initializing extension MIT-SHM
[     6.722] (II) Initializing extension XInputExtension
[     6.723] (II) Initializing extension XTEST
[     6.723] (II) Initializing extension BIG-REQUESTS
[     6.723] (II) Initializing extension SYNC
[     6.723] (II) Initializing extension XKEYBOARD
[     6.723] (II) Initializing extension XC-MISC
[     6.723] (II) Initializing extension SECURITY
[     6.723] (II) Initializing extension XFIXES
[     6.723] (II) Initializing extension RENDER
[     6.723] (II) Initializing extension RANDR
[     6.723] (II) Initializing extension COMPOSITE
[     6.723] (II) Initializing extension DAMAGE
[     6.723] (II) Initializing extension MIT-SCREEN-SAVER
[     6.723] (II) Initializing extension DOUBLE-BUFFER
[     6.723] (II) Initializing extension RECORD
[     6.723] (II) Initializing extension DPMS
[     6.723] (II) Initializing extension Present
[     6.723] (II) Initializing extension DRI3
[     6.724] (II) Initializing extension X-Resource
[     6.724] (II) Initializing extension XVideo
[     6.724] (II) Initializing extension XVideo-MotionCompensation
[     6.724] (II) Initializing extension GLX
[     6.724] (II) Initializing extension GLX
[     6.724] (II) Indirect GLX disabled.
[     6.727] (II) AIGLX: Loaded and initialized radeonsi
[     6.727] (II) GLX: Initialized DRI2 GL provider for screen 0
[     6.727] (II) Initializing extension XFree86-VidModeExtension
[     6.727] (II) Initializing extension XFree86-DGA
[     6.727] (II) Initializing extension XFree86-DRI
[     6.727] (II) Initializing extension DRI2
[     6.727] (II) Initializing extension NV-GLX
[     6.727] (II) Initializing extension NV-CONTROL
[     6.727] (II) AMDGPU(0): Setting screen physical size to 1524 x 571
[     6.883] (II) config/udev: Adding input device Asus Wireless Radio Control (/dev/input/event4)
[     6.883] (**) Asus Wireless Radio Control: Applying InputClass "libinput keyboard catchall"
[     6.883] (II) LoadModule: "libinput"
[     6.883] (II) Loading /usr/lib/xorg/modules/input/libinput_drv.so
[     6.885] (II) Module libinput: vendor="X.Org Foundation"
[     6.885] 	compiled for 1.21.1.3, module version = 1.2.1
[     6.885] 	Module class: X.Org XInput Driver
[     6.885] 	ABI class: X.Org XInput driver, version 24.4
[     6.885] (II) Using input driver 'libinput' for 'Asus Wireless Radio Control'
[     6.885] (II) systemd-logind: got fd for /dev/input/event4 13:68 fd 48 paused 0
[     6.885] (**) Asus Wireless Radio Control: always reports core events
[     6.885] (**) Option "Device" "/dev/input/event4"
[     6.890] (II) event4  - Asus Wireless Radio Control: is tagged by udev as: Keyboard
[     6.890] (II) event4  - Asus Wireless Radio Control: device is a keyboard
[     6.890] (II) event4  - Asus Wireless Radio Control: device removed
[     6.890] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/ATK4002:00/input/input4/event4"
[     6.890] (II) XINPUT: Adding extended input device "Asus Wireless Radio Control" (type: KEYBOARD, id 6)
[     6.890] (II) event4  - Asus Wireless Radio Control: is tagged by udev as: Keyboard
[     6.890] (II) event4  - Asus Wireless Radio Control: device is a keyboard
[     6.891] (II) config/udev: Adding input device Video Bus (/dev/input/event5)
[     6.891] (**) Video Bus: Applying InputClass "libinput keyboard catchall"
[     6.891] (II) Using input driver 'libinput' for 'Video Bus'
[     6.892] (II) systemd-logind: got fd for /dev/input/event5 13:69 fd 51 paused 0
[     6.892] (**) Video Bus: always reports core events
[     6.892] (**) Option "Device" "/dev/input/event5"
[     6.892] (II) event5  - Video Bus: is tagged by udev as: Keyboard
[     6.892] (II) event5  - Video Bus: device is a keyboard
[     6.892] (II) event5  - Video Bus: device removed
[     6.892] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/PNP0A08:00/device:01/LNXVIDEO:00/input/input5/event5"
[     6.892] (II) XINPUT: Adding extended input device "Video Bus" (type: KEYBOARD, id 7)
[     6.893] (II) event5  - Video Bus: is tagged by udev as: Keyboard
[     6.893] (II) event5  - Video Bus: device is a keyboard
[     6.893] (II) config/udev: Adding input device Video Bus (/dev/input/event6)
[     6.893] (**) Video Bus: Applying InputClass "libinput keyboard catchall"
[     6.893] (II) Using input driver 'libinput' for 'Video Bus'
[     6.894] (II) systemd-logind: got fd for /dev/input/event6 13:70 fd 52 paused 0
[     6.894] (**) Video Bus: always reports core events
[     6.894] (**) Option "Device" "/dev/input/event6"
[     6.894] (II) event6  - Video Bus: is tagged by udev as: Keyboard
[     6.894] (II) event6  - Video Bus: device is a keyboard
[     6.894] (II) event6  - Video Bus: device removed
[     6.894] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/PNP0A08:00/device:0f/LNXVIDEO:01/input/input6/event6"
[     6.894] (II) XINPUT: Adding extended input device "Video Bus" (type: KEYBOARD, id 8)
[     6.895] (II) event6  - Video Bus: is tagged by udev as: Keyboard
[     6.895] (II) event6  - Video Bus: device is a keyboard
[     6.895] (II) config/udev: Adding input device Power Button (/dev/input/event0)
[     6.895] (**) Power Button: Applying InputClass "libinput keyboard catchall"
[     6.895] (II) Using input driver 'libinput' for 'Power Button'
[     6.895] (II) systemd-logind: got fd for /dev/input/event0 13:64 fd 53 paused 0
[     6.895] (**) Power Button: always reports core events
[     6.895] (**) Option "Device" "/dev/input/event0"
[     6.896] (II) event0  - Power Button: is tagged by udev as: Keyboard
[     6.896] (II) event0  - Power Button: device is a keyboard
[     6.896] (II) event0  - Power Button: device removed
[     6.896] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/PNP0C0C:00/input/input0/event0"
[     6.896] (II) XINPUT: Adding extended input device "Power Button" (type: KEYBOARD, id 9)
[     6.896] (II) event0  - Power Button: is tagged by udev as: Keyboard
[     6.896] (II) event0  - Power Button: device is a keyboard
[     6.897] (II) config/udev: Adding input device Lid Switch (/dev/input/event2)
[     6.897] (II) No input driver specified, ignoring this device.
[     6.897] (II) This device may have been added with another device file.
[     6.897] (II) config/udev: Adding input device Sleep Button (/dev/input/event1)
[     6.897] (**) Sleep Button: Applying InputClass "libinput keyboard catchall"
[     6.897] (II) Using input driver 'libinput' for 'Sleep Button'
[     6.898] (II) systemd-logind: got fd for /dev/input/event1 13:65 fd 54 paused 0
[     6.898] (**) Sleep Button: always reports core events
[     6.898] (**) Option "Device" "/dev/input/event1"
[     6.898] (II) event1  - Sleep Button: is tagged by udev as: Keyboard
[     6.898] (II) event1  - Sleep Button: device is a keyboard
[     6.899] (II) event1  - Sleep Button: device removed
[     6.899] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/PNP0C0E:00/input/input1/event1"
[     6.899] (II) XINPUT: Adding extended input device "Sleep Button" (type: KEYBOARD, id 10)
[     6.899] (II) event1  - Sleep Button: is tagged by udev as: Keyboard
[     6.899] (II) event1  - Sleep Button: device is a keyboard
[     6.899] (II) config/udev: Adding input device HDA NVidia HDMI/DP,pcm=3 (/dev/input/event9)
[     6.899] (II) No input driver specified, ignoring this device.
[     6.899] (II) This device may have been added with another device file.
[     6.899] (II) config/udev: Adding input device HDA NVidia HDMI/DP,pcm=7 (/dev/input/event10)
[     6.899] (II) No input driver specified, ignoring this device.
[     6.899] (II) This device may have been added with another device file.
[     6.900] (II) config/udev: Adding input device HDA NVidia HDMI/DP,pcm=8 (/dev/input/event11)
[     6.900] (II) No input driver specified, ignoring this device.
[     6.900] (II) This device may have been added with another device file.
[     6.900] (II) config/udev: Adding input device HDA NVidia HDMI/DP,pcm=9 (/dev/input/event13)
[     6.900] (II) No input driver specified, ignoring this device.
[     6.900] (II) This device may have been added with another device file.
[     6.900] (II) config/udev: Adding input device HD-Audio Generic HDMI/DP,pcm=3 (/dev/input/event8)
[     6.900] (II) No input driver specified, ignoring this device.
[     6.900] (II) This device may have been added with another device file.
[     6.900] (II) config/udev: Adding input device Logitech Wireless Keyboard PID:4023 (/dev/input/event18)
[     6.900] (**) Logitech Wireless Keyboard PID:4023: Applying InputClass "libinput keyboard catchall"
[     6.900] (II) Using input driver 'libinput' for 'Logitech Wireless Keyboard PID:4023'
[     6.901] (II) systemd-logind: got fd for /dev/input/event18 13:82 fd 55 paused 0
[     6.901] (**) Logitech Wireless Keyboard PID:4023: always reports core events
[     6.901] (**) Option "Device" "/dev/input/event18"
[     6.902] (II) event18 - Logitech Wireless Keyboard PID:4023: is tagged by udev as: Keyboard
[     6.902] (II) event18 - Logitech Wireless Keyboard PID:4023: device is a keyboard
[     6.902] (II) event18 - Logitech Wireless Keyboard PID:4023: device removed
[     6.902] (II) libinput: Logitech Wireless Keyboard PID:4023: needs a virtual subdevice
[     6.902] (**) Option "config_info" "udev:/sys/devices/pci0000:00/0000:00:08.1/0000:06:00.3/usb1/1-2/1-2:1.1/0003:046D:C534.0002/0003:046D:4023.0004/input/input35/event18"
[     6.902] (II) XINPUT: Adding extended input device "Logitech Wireless Keyboard PID:4023" (type: MOUSE, id 11)
[     6.902] (**) Option "AccelerationScheme" "none"
[     6.902] (**) Logitech Wireless Keyboard PID:4023: (accel) selected scheme none/0
[     6.902] (**) Logitech Wireless Keyboard PID:4023: (accel) acceleration factor: 2.000
[     6.902] (**) Logitech Wireless Keyboard PID:4023: (accel) acceleration threshold: 4
[     6.903] (II) event18 - Logitech Wireless Keyboard PID:4023: is tagged by udev as: Keyboard
[     6.903] (II) event18 - Logitech Wireless Keyboard PID:4023: device is a keyboard
[     6.903] (II) config/udev: Adding input device Logitech Wireless Mouse (/dev/input/event19)
[     6.903] (**) Logitech Wireless Mouse: Applying InputClass "libinput pointer catchall"
[     6.903] (II) Using input driver 'libinput' for 'Logitech Wireless Mouse'
[     6.904] (II) systemd-logind: got fd for /dev/input/event19 13:83 fd 56 paused 0
[     6.904] (**) Logitech Wireless Mouse: always reports core events
[     6.904] (**) Option "Device" "/dev/input/event19"
[     6.905] (II) event19 - Logitech Wireless Mouse: is tagged by udev as: Mouse
[     6.905] (II) event19 - Logitech Wireless Mouse: device is a pointer
[     6.905] (II) event19 - Logitech Wireless Mouse: device removed
[     6.905] (**) Option "config_info" "udev:/sys/devices/pci0000:00/0000:00:08.1/0000:06:00.3/usb1/1-2/1-2:1.1/0003:046D:C534.0002/0003:046D:4058.0005/input/input36/event19"
[     6.905] (II) XINPUT: Adding extended input device "Logitech Wireless Mouse" (type: MOUSE, id 12)
[     6.905] (**) Option "AccelerationScheme" "none"
[     6.905] (**) Logitech Wireless Mouse: (accel) selected scheme none/0
[     6.905] (**) Logitech Wireless Mouse: (accel) acceleration factor: 2.000
[     6.905] (**) Logitech Wireless Mouse: (accel) acceleration threshold: 4
[     6.906] (II) event19 - Logitech Wireless Mouse: is tagged by udev as: Mouse
[     6.906] (II) event19 - Logitech Wireless Mouse: device is a pointer
[     6.906] (II) config/udev: Adding input device Logitech Wireless Mouse (/dev/input/mouse2)
[     6.906] (II) No input driver specified, ignoring this device.
[     6.907] (II) This device may have been added with another device file.
[     6.907] (II) config/udev: Adding input device USB2.0 HD UVC WebCam: USB2.0 HD (/dev/input/event17)
[     6.907] (**) USB2.0 HD UVC WebCam: USB2.0 HD: Applying InputClass "libinput keyboard catchall"
[     6.907] (II) Using input driver 'libinput' for 'USB2.0 HD UVC WebCam: USB2.0 HD'
[     6.908] (II) systemd-logind: got fd for /dev/input/event17 13:81 fd 57 paused 0
[     6.908] (**) USB2.0 HD UVC WebCam: USB2.0 HD: always reports core events
[     6.908] (**) Option "Device" "/dev/input/event17"
[     6.908] (II) event17 - USB2.0 HD UVC WebCam: USB2.0 HD: is tagged by udev as: Keyboard
[     6.908] (II) event17 - USB2.0 HD UVC WebCam: USB2.0 HD: device is a keyboard
[     6.908] (II) event17 - USB2.0 HD UVC WebCam: USB2.0 HD: device removed
[     6.908] (**) Option "config_info" "udev:/sys/devices/pci0000:00/0000:00:08.1/0000:06:00.3/usb1/1-4/1-4:1.0/input/input25/event17"
[     6.908] (II) XINPUT: Adding extended input device "USB2.0 HD UVC WebCam: USB2.0 HD" (type: KEYBOARD, id 13)
[     6.909] (II) event17 - USB2.0 HD UVC WebCam: USB2.0 HD: is tagged by udev as: Keyboard
[     6.909] (II) event17 - USB2.0 HD UVC WebCam: USB2.0 HD: device is a keyboard
[     6.909] (II) config/udev: Adding input device HD-Audio Generic Headphone (/dev/input/event14)
[     6.909] (II) No input driver specified, ignoring this device.
[     6.909] (II) This device may have been added with another device file.
[     6.910] (II) config/udev: Adding input device ELAN1203:00 04F3:307A Mouse (/dev/input/event12)
[     6.910] (**) ELAN1203:00 04F3:307A Mouse: Applying InputClass "libinput pointer catchall"
[     6.910] (II) Using input driver 'libinput' for 'ELAN1203:00 04F3:307A Mouse'
[     6.910] (II) systemd-logind: got fd for /dev/input/event12 13:76 fd 58 paused 0
[     6.910] (**) ELAN1203:00 04F3:307A Mouse: always reports core events
[     6.910] (**) Option "Device" "/dev/input/event12"
[     6.911] (II) event12 - ELAN1203:00 04F3:307A Mouse: is tagged by udev as: Mouse Pointingstick
[     6.911] (II) event12 - ELAN1203:00 04F3:307A Mouse: device is a pointer
[     6.911] (II) event12 - ELAN1203:00 04F3:307A Mouse: device removed
[     6.911] (**) Option "config_info" "udev:/sys/devices/platform/AMDI0010:03/i2c-0/i2c-ELAN1203:00/0018:04F3:307A.0003/input/input23/event12"
[     6.911] (II) XINPUT: Adding extended input device "ELAN1203:00 04F3:307A Mouse" (type: MOUSE, id 14)
[     6.911] (**) Option "AccelerationScheme" "none"
[     6.911] (**) ELAN1203:00 04F3:307A Mouse: (accel) selected scheme none/0
[     6.911] (**) ELAN1203:00 04F3:307A Mouse: (accel) acceleration factor: 2.000
[     6.911] (**) ELAN1203:00 04F3:307A Mouse: (accel) acceleration threshold: 4
[     6.912] (II) event12 - ELAN1203:00 04F3:307A Mouse: is tagged by udev as: Mouse Pointingstick
[     6.912] (II) event12 - ELAN1203:00 04F3:307A Mouse: device is a pointer
[     6.913] (II) config/udev: Adding input device ELAN1203:00 04F3:307A Mouse (/dev/input/mouse0)
[     6.913] (II) No input driver specified, ignoring this device.
[     6.913] (II) This device may have been added with another device file.
[     6.913] (II) config/udev: Adding input device ELAN1203:00 04F3:307A Touchpad (/dev/input/event16)
[     6.913] (**) ELAN1203:00 04F3:307A Touchpad: Applying InputClass "libinput touchpad catchall"
[     6.913] (II) Using input driver 'libinput' for 'ELAN1203:00 04F3:307A Touchpad'
[     6.914] (II) systemd-logind: got fd for /dev/input/event16 13:80 fd 59 paused 0
[     6.914] (**) ELAN1203:00 04F3:307A Touchpad: always reports core events
[     6.914] (**) Option "Device" "/dev/input/event16"
[     6.914] (II) event16 - ELAN1203:00 04F3:307A Touchpad: is tagged by udev as: Touchpad
[     6.915] (II) event16 - ELAN1203:00 04F3:307A Touchpad: device is a touchpad
[     6.915] (II) event16 - ELAN1203:00 04F3:307A Touchpad: device removed
[     6.916] (**) Option "config_info" "udev:/sys/devices/platform/AMDI0010:03/i2c-0/i2c-ELAN1203:00/0018:04F3:307A.0003/input/input24/event16"
[     6.916] (II) XINPUT: Adding extended input device "ELAN1203:00 04F3:307A Touchpad" (type: TOUCHPAD, id 15)
[     6.916] (**) Option "AccelerationScheme" "none"
[     6.916] (**) ELAN1203:00 04F3:307A Touchpad: (accel) selected scheme none/0
[     6.916] (**) ELAN1203:00 04F3:307A Touchpad: (accel) acceleration factor: 2.000
[     6.916] (**) ELAN1203:00 04F3:307A Touchpad: (accel) acceleration threshold: 4
[     6.916] (II) event16 - ELAN1203:00 04F3:307A Touchpad: is tagged by udev as: Touchpad
[     6.917] (II) event16 - ELAN1203:00 04F3:307A Touchpad: device is a touchpad
[     6.917] (II) config/udev: Adding input device ELAN1203:00 04F3:307A Touchpad (/dev/input/mouse1)
[     6.917] (II) No input driver specified, ignoring this device.
[     6.917] (II) This device may have been added with another device file.
[     6.917] (II) config/udev: Adding input device Asus WMI hotkeys (/dev/input/event15)
[     6.917] (**) Asus WMI hotkeys: Applying InputClass "libinput keyboard catchall"
[     6.917] (II) Using input driver 'libinput' for 'Asus WMI hotkeys'
[     6.918] (II) systemd-logind: got fd for /dev/input/event15 13:79 fd 60 paused 0
[     6.918] (**) Asus WMI hotkeys: always reports core events
[     6.918] (**) Option "Device" "/dev/input/event15"
[     6.919] (II) event15 - Asus WMI hotkeys: is tagged by udev as: Keyboard
[     6.919] (II) event15 - Asus WMI hotkeys: device is a keyboard
[     6.919] (II) event15 - Asus WMI hotkeys: device removed
[     6.919] (**) Option "config_info" "udev:/sys/devices/platform/asus-nb-wmi/input/input22/event15"
[     6.919] (II) XINPUT: Adding extended input device "Asus WMI hotkeys" (type: KEYBOARD, id 16)
[     6.919] (II) event15 - Asus WMI hotkeys: is tagged by udev as: Keyboard
[     6.919] (II) event15 - Asus WMI hotkeys: device is a keyboard
[     6.920] (II) config/udev: Adding input device AT Translated Set 2 keyboard (/dev/input/event3)
[     6.920] (**) AT Translated Set 2 keyboard: Applying InputClass "libinput keyboard catchall"
[     6.920] (II) Using input driver 'libinput' for 'AT Translated Set 2 keyboard'
[     6.920] (II) systemd-logind: got fd for /dev/input/event3 13:67 fd 61 paused 0
[     6.920] (**) AT Translated Set 2 keyboard: always reports core events
[     6.920] (**) Option "Device" "/dev/input/event3"
[     6.920] (II) event3  - AT Translated Set 2 keyboard: is tagged by udev as: Keyboard
[     6.921] (II) event3  - AT Translated Set 2 keyboard: device is a keyboard
[     6.921] (II) event3  - AT Translated Set 2 keyboard: device removed
[     6.921] (**) Option "config_info" "udev:/sys/devices/platform/i8042/serio0/input/input3/event3"
[     6.921] (II) XINPUT: Adding extended input device "AT Translated Set 2 keyboard" (type: KEYBOARD, id 17)
[     6.922] (II) event3  - AT Translated Set 2 keyboard: is tagged by udev as: Keyboard
[     6.922] (II) event3  - AT Translated Set 2 keyboard: device is a keyboard
[     6.922] (II) config/udev: Adding input device PC Speaker (/dev/input/event7)
[     6.922] (II) No input driver specified, ignoring this device.
[     6.922] (II) This device may have been added with another device file.
[     6.934] (**) Logitech Wireless Keyboard PID:4023: Applying InputClass "libinput keyboard catchall"
[     6.934] (II) Using input driver 'libinput' for 'Logitech Wireless Keyboard PID:4023'
[     6.934] (II) systemd-logind: returning pre-existing fd for /dev/input/event18 13:82
[     6.934] (**) Logitech Wireless Keyboard PID:4023: always reports core events
[     6.934] (**) Option "Device" "/dev/input/event18"
[     6.935] (II) libinput: Logitech Wireless Keyboard PID:4023: is a virtual subdevice
[     6.935] (**) Option "config_info" "udev:/sys/devices/pci0000:00/0000:00:08.1/0000:06:00.3/usb1/1-2/1-2:1.1/0003:046D:C534.0002/0003:046D:4023.0004/input/input35/event18"
[     6.935] (II) XINPUT: Adding extended input device "Logitech Wireless Keyboard PID:4023" (type: KEYBOARD, id 18)
[     7.237] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[     7.237] (II) AMDGPU(0): Using EDID range info for horizontal sync
[     7.237] (II) AMDGPU(0): Using EDID range info for vertical refresh
[     7.237] (II) AMDGPU(0): Printing DDC gathered Modelines:
[     7.237] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[     7.237] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[     7.239] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[     7.242] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[     7.242] (II) AMDGPU(0): Using hsync ranges from config file
[     7.242] (II) AMDGPU(0): Using vrefresh ranges from config file
[     7.242] (II) AMDGPU(0): Printing DDC gathered Modelines:
[     7.242] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[     7.242] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[     7.245] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[     7.245] (--) NVIDIA(GPU-0): DFP-0: disconnected
[     7.245] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[     7.245] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[     7.245] (--) NVIDIA(GPU-0): 
[     7.246] (--) NVIDIA(GPU-0): DFP-1: disconnected
[     7.246] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[     7.246] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[     7.246] (--) NVIDIA(GPU-0): 
[     8.263] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[     8.263] (II) AMDGPU(0): Using hsync ranges from config file
[     8.263] (II) AMDGPU(0): Using vrefresh ranges from config file
[     8.263] (II) AMDGPU(0): Printing DDC gathered Modelines:
[     8.263] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[     8.263] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[     8.265] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[     8.267] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[     8.267] (II) AMDGPU(0): Using hsync ranges from config file
[     8.267] (II) AMDGPU(0): Using vrefresh ranges from config file
[     8.267] (II) AMDGPU(0): Printing DDC gathered Modelines:
[     8.267] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[     8.267] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[     8.268] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[     8.268] (--) NVIDIA(GPU-0): DFP-0: disconnected
[     8.268] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[     8.268] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[     8.268] (--) NVIDIA(GPU-0): 
[     8.268] (--) NVIDIA(GPU-0): DFP-1: disconnected
[     8.268] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[     8.268] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[     8.268] (--) NVIDIA(GPU-0): 
[     8.293] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[     8.293] (II) AMDGPU(0): Using hsync ranges from config file
[     8.293] (II) AMDGPU(0): Using vrefresh ranges from config file
[     8.293] (II) AMDGPU(0): Printing DDC gathered Modelines:
[     8.293] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[     8.293] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[     8.294] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[     8.296] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[     8.296] (II) AMDGPU(0): Using hsync ranges from config file
[     8.296] (II) AMDGPU(0): Using vrefresh ranges from config file
[     8.296] (II) AMDGPU(0): Printing DDC gathered Modelines:
[     8.296] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[     8.296] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[     8.297] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[     8.297] (--) NVIDIA(GPU-0): DFP-0: disconnected
[     8.297] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[     8.297] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[     8.297] (--) NVIDIA(GPU-0): 
[     8.297] (--) NVIDIA(GPU-0): DFP-1: disconnected
[     8.297] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[     8.297] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[     8.297] (--) NVIDIA(GPU-0): 
[    14.599] (EE) event19 - Logitech Wireless Mouse: client bug: event processing lagging behind by 23ms, your system is too slow
[    14.600] (**) Option "fd" "48"
[    14.600] (II) event4  - Asus Wireless Radio Control: device removed
[    14.600] (**) Option "fd" "51"
[    14.600] (II) event5  - Video Bus: device removed
[    14.600] (**) Option "fd" "52"
[    14.600] (II) event6  - Video Bus: device removed
[    14.600] (**) Option "fd" "53"
[    14.600] (II) event0  - Power Button: device removed
[    14.600] (**) Option "fd" "54"
[    14.600] (II) event1  - Sleep Button: device removed
[    14.600] (**) Option "fd" "55"
[    14.600] (**) Option "fd" "56"
[    14.600] (II) event19 - Logitech Wireless Mouse: device removed
[    14.600] (**) Option "fd" "57"
[    14.600] (II) event17 - USB2.0 HD UVC WebCam: USB2.0 HD: device removed
[    14.600] (**) Option "fd" "58"
[    14.600] (II) event12 - ELAN1203:00 04F3:307A Mouse: device removed
[    14.600] (**) Option "fd" "59"
[    14.600] (II) event16 - ELAN1203:00 04F3:307A Touchpad: device removed
[    14.600] (**) Option "fd" "60"
[    14.600] (II) event15 - Asus WMI hotkeys: device removed
[    14.600] (**) Option "fd" "61"
[    14.600] (II) event3  - AT Translated Set 2 keyboard: device removed
[    14.600] (**) Option "fd" "55"
[    14.600] (II) event18 - Logitech Wireless Keyboard PID:4023: device removed
[    14.625] (II) UnloadModule: "libinput"
[    14.625] (II) systemd-logind: not releasing fd for 13:82, still in use
[    14.625] (II) UnloadModule: "libinput"
[    14.625] (II) systemd-logind: releasing fd for 13:67
[    14.651] (II) UnloadModule: "libinput"
[    14.651] (II) systemd-logind: releasing fd for 13:79
[    14.728] (II) UnloadModule: "libinput"
[    14.729] (II) systemd-logind: releasing fd for 13:80
[    14.805] (II) UnloadModule: "libinput"
[    14.805] (II) systemd-logind: releasing fd for 13:76
[    14.875] (II) UnloadModule: "libinput"
[    14.875] (II) systemd-logind: releasing fd for 13:81
[    14.925] (II) UnloadModule: "libinput"
[    14.925] (II) systemd-logind: releasing fd for 13:83
[    14.982] (II) UnloadModule: "libinput"
[    14.982] (II) systemd-logind: releasing fd for 13:82
[    15.002] (II) UnloadModule: "libinput"
[    15.002] (II) systemd-logind: releasing fd for 13:65
[    15.028] (II) UnloadModule: "libinput"
[    15.028] (II) systemd-logind: releasing fd for 13:64
[    15.049] (II) UnloadModule: "libinput"
[    15.049] (II) systemd-logind: releasing fd for 13:70
[    15.082] (II) UnloadModule: "libinput"
[    15.082] (II) systemd-logind: releasing fd for 13:69
[    15.119] (II) UnloadModule: "libinput"
[    15.119] (II) systemd-logind: releasing fd for 13:68
[    15.185] (II) NVIDIA(GPU-0): Deleting GPU-0
[    15.189] (WW) xf86CloseConsole: KDSETMODE failed: Input/output error
[    15.189] (WW) xf86CloseConsole: VT_GETMODE failed: Input/output error
[    15.363] (II) Server terminated successfully (0). Closing log file.

____________________________________________

*** /var/log/Xorg.1.log
*** ls: -rw-r--r-- 1 root nomade 59710 2022-10-16 08:28:14.251930172 -0300 /var/log/Xorg.1.log
[    13.879] _XSERVTransSocketUNIXCreateListener: ...SocketCreateListener() failed
[    13.879] _XSERVTransMakeAllCOTSServerListeners: server already running
[    13.879] (--) Log file renamed from "/var/log/Xorg.pid-1247.log" to "/var/log/Xorg.1.log"
[    13.880] 
X.Org X Server 1.21.1.4
X Protocol Version 11, Revision 0
[    13.880] Current Operating System: Linux nomade007 6.0.1-arch2-1 #1 SMP PREEMPT_DYNAMIC Thu, 13 Oct 2022 18:58:49 +0000 x86_64
[    13.880] Kernel command line: initrd=\amd-ucode.img initrd=\initramfs-linux.img root=PARTUUID=f407dfcd-5b75-c540-99c7-811fac3135b7 rw
[    13.880]  
[    13.880] Current version of pixman: 0.40.0
[    13.880] 	Before reporting problems, check http://wiki.x.org
	to make sure that you have the latest version.
[    13.880] Markers: (--) probed, (**) from config file, (==) default setting,
	(++) from command line, (!!) notice, (II) informational,
	(WW) warning, (EE) error, (NI) not implemented, (??) unknown.
[    13.880] (==) Log file: "/var/log/Xorg.1.log", Time: Sun Oct 16 05:28:00 2022
[    13.880] (==) Using system config directory "/usr/share/X11/xorg.conf.d"
[    13.880] (==) No Layout section.  Using the first Screen section.
[    13.880] (==) No screen section available. Using defaults.
[    13.880] (**) |-->Screen "Default Screen Section" (0)
[    13.880] (**) |   |-->Monitor "<default monitor>"
[    13.880] (==) No monitor specified for screen "Default Screen Section".
	Using a default monitor configuration.
[    13.880] (==) Automatically adding devices
[    13.880] (==) Automatically enabling devices
[    13.880] (==) Automatically adding GPU devices
[    13.880] (==) Automatically binding GPU devices
[    13.880] (==) Max clients allowed: 256, resource mask: 0x1fffff
[    13.880] (WW) The directory "/usr/share/fonts/misc" does not exist.
[    13.880] 	Entry deleted from font path.
[    13.880] (WW) The directory "/usr/share/fonts/OTF" does not exist.
[    13.880] 	Entry deleted from font path.
[    13.880] (WW) The directory "/usr/share/fonts/Type1" does not exist.
[    13.880] 	Entry deleted from font path.
[    13.880] (==) FontPath set to:
	/usr/share/fonts/TTF,
	/usr/share/fonts/100dpi,
	/usr/share/fonts/75dpi
[    13.880] (==) ModulePath set to "/usr/lib/xorg/modules"
[    13.880] (II) The server relies on udev to provide the list of input devices.
	If no devices become available, reconfigure udev or disable AutoAddDevices.
[    13.880] (II) Module ABI versions:
[    13.880] 	X.Org ANSI C Emulation: 0.4
[    13.880] 	X.Org Video Driver: 25.2
[    13.880] 	X.Org XInput driver : 24.4
[    13.880] 	X.Org Server Extension : 10.0
[    13.880] (++) using VT number 2

[    13.881] (II) systemd-logind: took control of session /org/freedesktop/login1/session/_33
[    13.882] (II) xfree86: Adding drm device (/dev/dri/card1)
[    13.882] (II) Platform probe for /sys/devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm/card1
[    13.882] (II) systemd-logind: got fd for /dev/dri/card1 226:1 fd 15 paused 0
[    13.882] (II) xfree86: Adding drm device (/dev/dri/card0)
[    13.882] (II) Platform probe for /sys/devices/pci0000:00/0000:00:08.1/0000:06:00.0/drm/card0
[    13.882] (II) systemd-logind: got fd for /dev/dri/card0 226:0 fd 16 paused 0
[    13.883] (**) OutputClass "nvidia" ModulePath extended to "/usr/lib/nvidia/xorg,/usr/lib/xorg/modules,/usr/lib/xorg/modules"
[    13.884] (--) PCI: (1@0:0:0) 10de:2520:1043:16a2 rev 161, Mem @ 0xfb000000/16777216, 0xfc00000000/8589934592, 0xfe00000000/33554432, I/O @ 0x0000f000/128, BIOS @ 0x????????/524288
[    13.884] (--) PCI:*(6@0:0:0) 1002:1638:1043:16a2 rev 197, Mem @ 0xfe10000000/268435456, 0xfe20000000/2097152, 0xfc500000/524288, I/O @ 0x0000d000/256
[    13.884] (WW) Open ACPI failed (/var/run/acpid.socket) (No such file or directory)
[    13.884] (II) LoadModule: "glx"
[    13.884] (II) Loading /usr/lib/xorg/modules/extensions/libglx.so
[    13.885] (II) Module glx: vendor="X.Org Foundation"
[    13.885] 	compiled for 1.21.1.4, module version = 1.0.0
[    13.885] 	ABI class: X.Org Server Extension, version 10.0
[    13.885] (II) Applying OutputClass "AMDgpu" to /dev/dri/card0
[    13.885] 	loading driver: amdgpu
[    13.885] (II) Applying OutputClass "nvidia" to /dev/dri/card1
[    13.885] 	loading driver: nvidia
[    13.885] (==) Matched amdgpu as autoconfigured driver 0
[    13.885] (==) Matched ati as autoconfigured driver 1
[    13.885] (==) Matched nvidia as autoconfigured driver 2
[    13.885] (==) Matched nouveau as autoconfigured driver 3
[    13.885] (==) Matched nv as autoconfigured driver 4
[    13.885] (==) Matched modesetting as autoconfigured driver 5
[    13.885] (==) Matched fbdev as autoconfigured driver 6
[    13.885] (==) Matched vesa as autoconfigured driver 7
[    13.885] (==) Assigned the driver to the xf86ConfigLayout
[    13.885] (II) LoadModule: "amdgpu"
[    13.885] (II) Loading /usr/lib/xorg/modules/drivers/amdgpu_drv.so
[    13.885] (II) Module amdgpu: vendor="X.Org Foundation"
[    13.885] 	compiled for 1.21.1.3, module version = 22.0.0
[    13.885] 	Module class: X.Org Video Driver
[    13.886] 	ABI class: X.Org Video Driver, version 25.2
[    13.886] (II) LoadModule: "ati"
[    13.886] (WW) Warning, couldn't open module ati
[    13.886] (EE) Failed to load module "ati" (module does not exist, 0)
[    13.886] (II) LoadModule: "nvidia"
[    13.886] (II) Loading /usr/lib/xorg/modules/drivers/nvidia_drv.so
[    13.886] (II) Module nvidia: vendor="NVIDIA Corporation"
[    13.886] 	compiled for 1.6.99.901, module version = 1.0.0
[    13.886] 	Module class: X.Org Video Driver
[    13.886] (II) LoadModule: "nouveau"
[    13.886] (WW) Warning, couldn't open module nouveau
[    13.886] (EE) Failed to load module "nouveau" (module does not exist, 0)
[    13.886] (II) LoadModule: "nv"
[    13.886] (WW) Warning, couldn't open module nv
[    13.886] (EE) Failed to load module "nv" (module does not exist, 0)
[    13.886] (II) LoadModule: "modesetting"
[    13.886] (II) Loading /usr/lib/xorg/modules/drivers/modesetting_drv.so
[    13.886] (II) Module modesetting: vendor="X.Org Foundation"
[    13.886] 	compiled for 1.21.1.4, module version = 1.21.1
[    13.886] 	Module class: X.Org Video Driver
[    13.886] 	ABI class: X.Org Video Driver, version 25.2
[    13.886] (II) LoadModule: "fbdev"
[    13.886] (II) Loading /usr/lib/xorg/modules/drivers/fbdev_drv.so
[    13.886] (II) Module fbdev: vendor="X.Org Foundation"
[    13.886] 	compiled for 1.21.1.1, module version = 0.5.0
[    13.886] 	Module class: X.Org Video Driver
[    13.886] 	ABI class: X.Org Video Driver, version 25.2
[    13.886] (II) LoadModule: "vesa"
[    13.886] (II) Loading /usr/lib/xorg/modules/drivers/vesa_drv.so
[    13.886] (II) Module vesa: vendor="X.Org Foundation"
[    13.886] 	compiled for 1.21.1.3, module version = 2.5.0
[    13.886] 	Module class: X.Org Video Driver
[    13.886] 	ABI class: X.Org Video Driver, version 25.2
[    13.886] (II) AMDGPU: Driver for AMD Radeon:
	All GPUs supported by the amdgpu kernel driver
[    13.886] (II) NVIDIA dlloader X Driver  520.56.06  Thu Oct  6 21:29:26 UTC 2022
[    13.886] (II) NVIDIA Unified Driver for all Supported NVIDIA GPUs
[    13.886] (II) modesetting: Driver for Modesetting Kernel Drivers: kms
[    13.886] (II) FBDEV: driver for framebuffer: fbdev
[    13.886] (II) VESA: driver for VESA chipsets: vesa
[    13.891] (WW) Falling back to old probe method for modesetting
[    13.891] (WW) Falling back to old probe method for fbdev
[    13.891] (II) Loading sub module "fbdevhw"
[    13.891] (II) LoadModule: "fbdevhw"
[    13.891] (II) Loading /usr/lib/xorg/modules/libfbdevhw.so
[    13.891] (II) Module fbdevhw: vendor="X.Org Foundation"
[    13.891] 	compiled for 1.21.1.4, module version = 0.0.2
[    13.891] 	ABI class: X.Org Video Driver, version 25.2
[    13.891] (II) systemd-logind: releasing fd for 226:1
[    13.892] (II) Loading sub module "fb"
[    13.892] (II) LoadModule: "fb"
[    13.892] (II) Module "fb" already built-in
[    13.892] (II) Loading sub module "wfb"
[    13.892] (II) LoadModule: "wfb"
[    13.892] (II) Loading /usr/lib/xorg/modules/libwfb.so
[    13.892] (II) Module wfb: vendor="X.Org Foundation"
[    13.892] 	compiled for 1.21.1.4, module version = 1.0.0
[    13.892] 	ABI class: X.Org ANSI C Emulation, version 0.4
[    13.892] (II) Loading sub module "ramdac"
[    13.892] (II) LoadModule: "ramdac"
[    13.892] (II) Module "ramdac" already built-in
[    13.892] (II) AMDGPU(0): Creating default Display subsection in Screen section
	"Default Screen Section" for depth/fbbpp 24/32
[    13.892] (==) AMDGPU(0): Depth 24, (--) framebuffer bpp 32
[    13.892] (II) AMDGPU(0): Pixel depth = 24 bits stored in 4 bytes (32 bpp pixmaps)
[    13.892] (==) AMDGPU(0): Default visual is TrueColor
[    13.892] (==) AMDGPU(0): RGB weight 888
[    13.892] (II) AMDGPU(0): Using 8 bits per RGB (8 bit DAC)
[    13.892] (--) AMDGPU(0): Chipset: "Unknown AMD Radeon GPU" (ChipID = 0x1638)
[    13.892] (II) Loading sub module "fb"
[    13.892] (II) LoadModule: "fb"
[    13.892] (II) Module "fb" already built-in
[    13.892] (II) Loading sub module "dri2"
[    13.892] (II) LoadModule: "dri2"
[    13.892] (II) Module "dri2" already built-in
[    13.909] (II) Loading sub module "glamoregl"
[    13.909] (II) LoadModule: "glamoregl"
[    13.909] (II) Loading /usr/lib/xorg/modules/libglamoregl.so
[    13.911] (II) Module glamoregl: vendor="X.Org Foundation"
[    13.911] 	compiled for 1.21.1.4, module version = 1.0.1
[    13.911] 	ABI class: X.Org ANSI C Emulation, version 0.4
[    13.918] (II) AMDGPU(0): glamor X acceleration enabled on RENOIR (renoir, LLVM 14.0.6, DRM 3.48, 6.0.1-arch2-1)
[    13.918] (II) AMDGPU(0): glamor detected, initialising EGL layer.
[    13.918] (==) AMDGPU(0): TearFree property default: auto
[    13.918] (==) AMDGPU(0): VariableRefresh: disabled
[    13.918] (==) AMDGPU(0): AsyncFlipSecondaries: disabled
[    13.918] (II) AMDGPU(0): KMS Pageflipping: enabled
[    14.028] (II) AMDGPU(0): Output eDP has no monitor section
[    14.029] (II) AMDGPU(0): Output HDMI-A-0 has no monitor section
[    14.049] (II) AMDGPU(0): EDID for output eDP
[    14.049] (II) AMDGPU(0): Manufacturer: NCP  Model: 4d  Serial#: 0
[    14.049] (II) AMDGPU(0): Year: 2019  Week: 51
[    14.049] (II) AMDGPU(0): EDID Version: 1.4
[    14.049] (II) AMDGPU(0): Digital Display Input
[    14.049] (II) AMDGPU(0): 8 bits per channel
[    14.049] (II) AMDGPU(0): Digital interface is DisplayPort
[    14.049] (II) AMDGPU(0): Max Image Size [cm]: horiz.: 34  vert.: 19
[    14.049] (II) AMDGPU(0): Gamma: 2.20
[    14.050] (II) AMDGPU(0): No DPMS capabilities specified
[    14.050] (II) AMDGPU(0): Supported color encodings: RGB 4:4:4 
[    14.050] (II) AMDGPU(0): First detailed timing is preferred mode
[    14.050] (II) AMDGPU(0): Preferred mode is native pixel format and refresh rate
[    14.050] (II) AMDGPU(0): Display is continuous-frequency
[    14.050] (II) AMDGPU(0): redX: 0.595 redY: 0.361   greenX: 0.346 greenY: 0.555
[    14.050] (II) AMDGPU(0): blueX: 0.157 blueY: 0.106   whiteX: 0.312 whiteY: 0.328
[    14.050] (II) AMDGPU(0): Manufacturer's mask: 0
[    14.050] (II) AMDGPU(0): Supported detailed timing:
[    14.050] (II) AMDGPU(0): clock: 354.7 MHz   Image Size:  344 x 194 mm
[    14.050] (II) AMDGPU(0): h_active: 1920  h_sync: 1968  h_sync_end 2000 h_blank_end 2180 h_border: 0
[    14.050] (II) AMDGPU(0): v_active: 1080  v_sync: 1083  v_sync_end 1088 v_blanking: 1130 v_border: 0
[    14.050] (II) AMDGPU(0): Supported detailed timing:
[    14.050] (II) AMDGPU(0): clock: 147.8 MHz   Image Size:  344 x 194 mm
[    14.050] (II) AMDGPU(0): h_active: 1920  h_sync: 1968  h_sync_end 2000 h_blank_end 2180 h_border: 0
[    14.050] (II) AMDGPU(0): v_active: 1080  v_sync: 1083  v_sync_end 1088 v_blanking: 1130 v_border: 0
[    14.050] (II) AMDGPU(0): Ranges: V min: 48 V max: 144 Hz, H min: 163 H max: 163 kHz, PixClock max 355 MHz
[    14.050] (II) AMDGPU(0):  LM156LF-2F03
[    14.050] (II) AMDGPU(0): EDID (in hex):
[    14.050] (II) AMDGPU(0): 	00ffffffffffff0038704d0000000000
[    14.050] (II) AMDGPU(0): 	331d0104a5221378036850985c588e28
[    14.050] (II) AMDGPU(0): 	1b505400000001010101010101010101
[    14.050] (II) AMDGPU(0): 	010101010101918a8004713832403020
[    14.050] (II) AMDGPU(0): 	350058c21000001abd39800471383240
[    14.050] (II) AMDGPU(0): 	3020350058c21000001a000000fd0030
[    14.050] (II) AMDGPU(0): 	90a3a323010a202020202020000000fe
[    14.050] (II) AMDGPU(0): 	004c4d3135364c462d324630330a0035
[    14.050] (II) AMDGPU(0): Printing probed modes for output eDP
[    14.050] (II) AMDGPU(0): Modeline "1920x1080"x144.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[    14.050] (II) AMDGPU(0): Modeline "1920x1080"x120.0  354.73  1920 1968 2000 2180  1080 1309 1314 1356 +hsync -vsync (162.7 kHz e)
[    14.050] (II) AMDGPU(0): Modeline "1920x1080"x96.0  354.73  1920 1968 2000 2180  1080 1648 1653 1695 +hsync -vsync (162.7 kHz e)
[    14.050] (II) AMDGPU(0): Modeline "1920x1080"x72.0  354.73  1920 1968 2000 2180  1080 2213 2218 2260 +hsync -vsync (162.7 kHz e)
[    14.050] (II) AMDGPU(0): Modeline "1920x1080"x60.0  354.73  1920 1968 2000 2180  1080 2665 2670 2712 +hsync -vsync (162.7 kHz e)
[    14.050] (II) AMDGPU(0): Modeline "1920x1080"x50.0  354.73  1920 1968 2000 2180  1080 3207 3212 3254 +hsync -vsync (162.7 kHz e)
[    14.050] (II) AMDGPU(0): Modeline "1920x1080"x48.0  354.73  1920 1968 2000 2180  1080 3343 3348 3390 +hsync -vsync (162.7 kHz e)
[    14.050] (II) AMDGPU(0): Modeline "1920x1080"x60.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[    14.050] (II) AMDGPU(0): Modeline "1680x1050"x144.0  354.73  1680 1968 2000 2180  1050 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[    14.050] (II) AMDGPU(0): Modeline "1280x1024"x144.0  354.73  1280 1968 2000 2180  1024 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[    14.050] (II) AMDGPU(0): Modeline "1440x900"x144.0  354.73  1440 1968 2000 2180  900 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[    14.050] (II) AMDGPU(0): Modeline "1280x800"x144.0  354.73  1280 1968 2000 2180  800 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[    14.050] (II) AMDGPU(0): Modeline "1280x720"x144.0  354.73  1280 1968 2000 2180  720 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[    14.050] (II) AMDGPU(0): Modeline "1024x768"x144.0  354.73  1024 1968 2000 2180  768 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[    14.050] (II) AMDGPU(0): Modeline "800x600"x144.0  354.73  800 1968 2000 2180  600 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[    14.050] (II) AMDGPU(0): Modeline "640x480"x144.0  354.73  640 1968 2000 2180  480 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[    14.051] (II) AMDGPU(0): EDID for output HDMI-A-0
[    14.051] (II) AMDGPU(0): Manufacturer: SAM  Model: c4e  Serial#: 1113216587
[    14.051] (II) AMDGPU(0): Year: 2020  Week: 41
[    14.051] (II) AMDGPU(0): EDID Version: 1.3
[    14.051] (II) AMDGPU(0): Digital Display Input
[    14.051] (II) AMDGPU(0): Max Image Size [cm]: horiz.: 61  vert.: 35
[    14.051] (II) AMDGPU(0): Gamma: 2.20
[    14.051] (II) AMDGPU(0): DPMS capabilities: Off
[    14.051] (II) AMDGPU(0): Supported color encodings: RGB 4:4:4 YCrCb 4:4:4 
[    14.051] (II) AMDGPU(0): First detailed timing is preferred mode
[    14.051] (II) AMDGPU(0): redX: 0.634 redY: 0.341   greenX: 0.312 greenY: 0.636
[    14.051] (II) AMDGPU(0): blueX: 0.158 blueY: 0.062   whiteX: 0.312 whiteY: 0.329
[    14.051] (II) AMDGPU(0): Supported established timings:
[    14.051] (II) AMDGPU(0): 720x400@70Hz
[    14.051] (II) AMDGPU(0): 640x480@60Hz
[    14.051] (II) AMDGPU(0): 640x480@67Hz
[    14.051] (II) AMDGPU(0): 640x480@72Hz
[    14.051] (II) AMDGPU(0): 640x480@75Hz
[    14.051] (II) AMDGPU(0): 800x600@56Hz
[    14.051] (II) AMDGPU(0): 800x600@60Hz
[    14.051] (II) AMDGPU(0): 800x600@72Hz
[    14.051] (II) AMDGPU(0): 800x600@75Hz
[    14.051] (II) AMDGPU(0): 832x624@75Hz
[    14.051] (II) AMDGPU(0): 1024x768@60Hz
[    14.051] (II) AMDGPU(0): 1024x768@70Hz
[    14.051] (II) AMDGPU(0): 1024x768@75Hz
[    14.051] (II) AMDGPU(0): 1280x1024@75Hz
[    14.051] (II) AMDGPU(0): 1152x864@75Hz
[    14.051] (II) AMDGPU(0): Manufacturer's mask: 0
[    14.051] (II) AMDGPU(0): Supported standard timings:
[    14.051] (II) AMDGPU(0): #0: hsize: 1152  vsize 864  refresh: 75  vid: 20337
[    14.051] (II) AMDGPU(0): #1: hsize: 1280  vsize 800  refresh: 60  vid: 129
[    14.051] (II) AMDGPU(0): #2: hsize: 1280  vsize 720  refresh: 60  vid: 49281
[    14.051] (II) AMDGPU(0): #3: hsize: 1280  vsize 1024  refresh: 60  vid: 32897
[    14.051] (II) AMDGPU(0): #4: hsize: 1440  vsize 900  refresh: 60  vid: 149
[    14.051] (II) AMDGPU(0): #5: hsize: 1600  vsize 900  refresh: 60  vid: 49321
[    14.051] (II) AMDGPU(0): #6: hsize: 1680  vsize 1050  refresh: 60  vid: 179
[    14.051] (II) AMDGPU(0): Supported detailed timing:
[    14.051] (II) AMDGPU(0): clock: 297.0 MHz   Image Size:  608 x 345 mm
[    14.051] (II) AMDGPU(0): h_active: 3840  h_sync: 4016  h_sync_end 4104 h_blank_end 4400 h_border: 0
[    14.051] (II) AMDGPU(0): v_active: 2160  v_sync: 2168  v_sync_end 2178 v_blanking: 2250 v_border: 0
[    14.051] (II) AMDGPU(0): Ranges: V min: 24 V max: 75 Hz, H min: 30 H max: 90 kHz, PixClock max 305 MHz
[    14.051] (II) AMDGPU(0): Monitor name: U28E590
[    14.051] (II) AMDGPU(0): Serial No: H4ZNA00044
[    14.051] (II) AMDGPU(0): Supported detailed timing:
[    14.051] (II) AMDGPU(0): clock: 148.5 MHz   Image Size:  608 x 345 mm
[    14.051] (II) AMDGPU(0): h_active: 1920  h_sync: 2008  h_sync_end 2052 h_blank_end 2200 h_border: 0
[    14.051] (II) AMDGPU(0): v_active: 1080  v_sync: 1084  v_sync_end 1089 v_blanking: 1125 v_border: 0
[    14.051] (II) AMDGPU(0): Supported detailed timing:
[    14.051] (II) AMDGPU(0): clock: 148.5 MHz   Image Size:  608 x 345 mm
[    14.051] (II) AMDGPU(0): h_active: 1920  h_sync: 2448  h_sync_end 2492 h_blank_end 2640 h_border: 0
[    14.051] (II) AMDGPU(0): v_active: 1080  v_sync: 1084  v_sync_end 1089 v_blanking: 1125 v_border: 0
[    14.051] (II) AMDGPU(0): Supported detailed timing:
[    14.051] (II) AMDGPU(0): clock: 74.2 MHz   Image Size:  608 x 345 mm
[    14.051] (II) AMDGPU(0): h_active: 1280  h_sync: 1390  h_sync_end 1430 h_blank_end 1650 h_border: 0
[    14.051] (II) AMDGPU(0): v_active: 720  v_sync: 725  v_sync_end 730 v_blanking: 750 v_border: 0
[    14.051] (II) AMDGPU(0): Supported detailed timing:
[    14.051] (II) AMDGPU(0): clock: 241.5 MHz   Image Size:  608 x 345 mm
[    14.051] (II) AMDGPU(0): h_active: 2560  h_sync: 2608  h_sync_end 2640 h_blank_end 2720 h_border: 0
[    14.051] (II) AMDGPU(0): v_active: 1440  v_sync: 1443  v_sync_end 1448 v_blanking: 1481 v_border: 0
[    14.051] (II) AMDGPU(0): Number of EDID sections to follow: 1
[    14.051] (II) AMDGPU(0): EDID (in hex):
[    14.051] (II) AMDGPU(0): 	00ffffffffffff004c2d4e0c4b565a42
[    14.051] (II) AMDGPU(0): 	291e0103803d23782a5fb1a2574fa228
[    14.051] (II) AMDGPU(0): 	0f5054bfef80714f810081c081809500
[    14.051] (II) AMDGPU(0): 	a9c0b300010104740030f2705a80b058
[    14.051] (II) AMDGPU(0): 	8a0060592100001e000000fd00184b1e
[    14.051] (II) AMDGPU(0): 	5a1e000a202020202020000000fc0055
[    14.051] (II) AMDGPU(0): 	3238453539300a2020202020000000ff
[    14.051] (II) AMDGPU(0): 	0048345a4e4130303034340a202001d3
[    14.051] (II) AMDGPU(0): 	020324f0495f10041f13031220222309
[    14.051] (II) AMDGPU(0): 	0707830100006d030c001000803c2010
[    14.051] (II) AMDGPU(0): 	60010203023a801871382d40582c4500
[    14.051] (II) AMDGPU(0): 	60592100001e023a80d072382d40102c
[    14.051] (II) AMDGPU(0): 	458060592100001e011d007251d01e20
[    14.051] (II) AMDGPU(0): 	6e28550060592100001e565e00a0a0a0
[    14.051] (II) AMDGPU(0): 	29503020350060592100001a00000000
[    14.051] (II) AMDGPU(0): 	00000000000000000000000000000067
[    14.051] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[    14.051] (II) AMDGPU(0): Printing probed modes for output HDMI-A-0
[    14.051] (II) AMDGPU(0): Modeline "3840x2160"x30.0  297.00  3840 4016 4104 4400  2160 2168 2178 2250 +hsync +vsync (67.5 kHz eP)
[    14.051] (II) AMDGPU(0): Modeline "3840x2160"x25.0  297.00  3840 4896 4984 5280  2160 2168 2178 2250 +hsync +vsync (56.2 kHz e)
[    14.051] (II) AMDGPU(0): Modeline "3840x2160"x24.0  297.00  3840 5116 5204 5500  2160 2168 2178 2250 +hsync +vsync (54.0 kHz e)
[    14.051] (II) AMDGPU(0): Modeline "3840x2160"x30.0  296.70  3840 4016 4104 4400  2160 2168 2178 2250 +hsync +vsync (67.4 kHz e)
[    14.051] (II) AMDGPU(0): Modeline "3840x2160"x24.0  296.70  3840 5116 5204 5500  2160 2168 2178 2250 +hsync +vsync (53.9 kHz e)
[    14.051] (II) AMDGPU(0): Modeline "2560x1440"x60.0  241.50  2560 2608 2640 2720  1440 1443 1448 1481 +hsync -vsync (88.8 kHz e)
[    14.051] (II) AMDGPU(0): Modeline "1920x1200"x30.0  297.00  1920 4016 4104 4400  1200 2168 2178 2250 +hsync +vsync (67.5 kHz e)
[    14.051] (II) AMDGPU(0): Modeline "1920x1080"x60.0  148.50  1920 2008 2052 2200  1080 1084 1089 1125 +hsync +vsync (67.5 kHz e)
[    14.051] (II) AMDGPU(0): Modeline "1920x1080"x50.0  148.50  1920 2448 2492 2640  1080 1084 1089 1125 +hsync +vsync (56.2 kHz e)
[    14.051] (II) AMDGPU(0): Modeline "1920x1080"x59.9  148.35  1920 2008 2052 2200  1080 1084 1089 1125 +hsync +vsync (67.4 kHz e)
[    14.051] (II) AMDGPU(0): Modeline "1920x1080"x30.0   74.25  1920 2008 2052 2200  1080 1084 1089 1125 +hsync +vsync (33.8 kHz e)
[    14.051] (II) AMDGPU(0): Modeline "1920x1080"x24.0   74.25  1920 2558 2602 2750  1080 1084 1089 1125 +hsync +vsync (27.0 kHz e)
[    14.051] (II) AMDGPU(0): Modeline "1920x1080"x30.0   74.18  1920 2008 2052 2200  1080 1084 1089 1125 +hsync +vsync (33.7 kHz e)
[    14.051] (II) AMDGPU(0): Modeline "1920x1080"x24.0   74.18  1920 2558 2602 2750  1080 1084 1089 1125 +hsync +vsync (27.0 kHz e)
[    14.051] (II) AMDGPU(0): Modeline "1600x1200"x30.0  297.00  1600 4016 4104 4400  1200 2168 2178 2250 +hsync +vsync (67.5 kHz e)
[    14.051] (II) AMDGPU(0): Modeline "1680x1050"x59.9  119.00  1680 1728 1760 1840  1050 1053 1059 1080 +hsync -vsync (64.7 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "1600x900"x60.0  108.00  1600 1624 1704 1800  900 901 904 1000 +hsync +vsync (60.0 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "1280x1024"x75.0  135.00  1280 1296 1440 1688  1024 1025 1028 1066 +hsync +vsync (80.0 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "1280x1024"x60.0  108.00  1280 1328 1440 1688  1024 1025 1028 1066 +hsync +vsync (64.0 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "1440x900"x59.9   88.75  1440 1488 1520 1600  900 903 909 926 +hsync -vsync (55.5 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "1280x800"x59.9   71.00  1280 1328 1360 1440  800 803 809 823 +hsync -vsync (49.3 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "1152x864"x75.0  108.00  1152 1216 1344 1600  864 865 868 900 +hsync +vsync (67.5 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "1280x720"x60.0   74.25  1280 1390 1430 1650  720 725 730 750 +hsync +vsync (45.0 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "1280x720"x50.0   74.25  1280 1720 1760 1980  720 725 730 750 +hsync +vsync (37.5 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "1280x720"x59.9   74.18  1280 1390 1430 1650  720 725 730 750 +hsync +vsync (45.0 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "1024x768"x75.0   78.75  1024 1040 1136 1312  768 769 772 800 +hsync +vsync (60.0 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "1024x768"x70.1   75.00  1024 1048 1184 1328  768 771 777 806 -hsync -vsync (56.5 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "1024x768"x60.0   65.00  1024 1048 1184 1344  768 771 777 806 -hsync -vsync (48.4 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "832x624"x74.6   57.28  832 864 928 1152  624 625 628 667 -hsync -vsync (49.7 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "800x600"x72.2   50.00  800 856 976 1040  600 637 643 666 +hsync +vsync (48.1 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "800x600"x75.0   49.50  800 816 896 1056  600 601 604 625 +hsync +vsync (46.9 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "800x600"x60.3   40.00  800 840 968 1056  600 601 605 628 +hsync +vsync (37.9 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "800x600"x56.2   36.00  800 824 896 1024  600 601 603 625 +hsync +vsync (35.2 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "720x576"x50.0   27.00  720 732 796 864  576 581 586 625 -hsync -vsync (31.2 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "720x480"x60.0   27.03  720 736 798 858  480 489 495 525 -hsync -vsync (31.5 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "720x480"x59.9   27.00  720 736 798 858  480 489 495 525 -hsync -vsync (31.5 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "640x480"x75.0   31.50  640 656 720 840  480 481 484 500 -hsync -vsync (37.5 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "640x480"x72.8   31.50  640 664 704 832  480 489 492 520 -hsync -vsync (37.9 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "640x480"x66.7   30.24  640 704 768 864  480 483 486 525 -hsync -vsync (35.0 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "640x480"x60.0   25.20  640 656 752 800  480 490 492 525 -hsync -vsync (31.5 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "640x480"x59.9   25.18  640 656 752 800  480 490 492 525 -hsync -vsync (31.5 kHz e)
[    14.052] (II) AMDGPU(0): Modeline "720x400"x70.1   28.32  720 738 846 900  400 412 414 449 -hsync +vsync (31.5 kHz e)
[    14.052] (II) AMDGPU(0): Output eDP connected
[    14.052] (II) AMDGPU(0): Output HDMI-A-0 connected
[    14.052] (II) AMDGPU(0): Using spanning desktop for initial modes
[    14.052] (II) AMDGPU(0): Output eDP using initial mode 1920x1080 +0+0
[    14.052] (II) AMDGPU(0): Output HDMI-A-0 using initial mode 3840x2160 +1920+0
[    14.052] (II) AMDGPU(0): mem size init: gart size :7c641d000 vram size: s:1e715000 visible:1e715000
[    14.052] (==) AMDGPU(0): DPI set to (96, 96)
[    14.052] (==) AMDGPU(0): Using gamma correction (1.0, 1.0, 1.0)
[    14.052] (II) Loading sub module "ramdac"
[    14.052] (II) LoadModule: "ramdac"
[    14.052] (II) Module "ramdac" already built-in
[    14.052] (==) NVIDIA(G0): Depth 24, (==) framebuffer bpp 32
[    14.052] (==) NVIDIA(G0): RGB weight 888
[    14.052] (==) NVIDIA(G0): Default visual is TrueColor
[    14.052] (==) NVIDIA(G0): Using gamma correction (1.0, 1.0, 1.0)
[    14.052] (II) Applying OutputClass "nvidia" options to /dev/dri/card1
[    14.052] (**) NVIDIA(G0): Option "AllowEmptyInitialConfiguration"
[    14.052] (**) NVIDIA(G0): Enabling 2D acceleration
[    14.052] (II) Loading sub module "glxserver_nvidia"
[    14.052] (II) LoadModule: "glxserver_nvidia"
[    14.052] (II) Loading /usr/lib/nvidia/xorg/libglxserver_nvidia.so
[    14.056] (II) Module glxserver_nvidia: vendor="NVIDIA Corporation"
[    14.056] 	compiled for 1.6.99.901, module version = 1.0.0
[    14.056] 	Module class: X.Org Server Extension
[    14.056] (II) NVIDIA GLX Module  520.56.06  Thu Oct  6 21:26:26 UTC 2022
[    14.056] (II) NVIDIA: The X server supports PRIME Render Offload.
[    14.056] (--) NVIDIA(0): Valid display device(s) on GPU-0 at PCI:1:0:0
[    14.056] (--) NVIDIA(0):     DFP-0
[    14.056] (--) NVIDIA(0):     DFP-1
[    14.057] (II) NVIDIA(G0): NVIDIA GPU NVIDIA GeForce RTX 3060 Laptop GPU (GA106-A) at
[    14.057] (II) NVIDIA(G0):     PCI:1:0:0 (GPU-0)
[    14.057] (--) NVIDIA(G0): Memory: 6291456 kBytes
[    14.057] (--) NVIDIA(G0): VideoBIOS: 94.06.17.00.5f
[    14.057] (II) NVIDIA(G0): Detected PCI Express Link width: 16X
[    14.057] (--) NVIDIA(GPU-0): DFP-0: disconnected
[    14.057] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[    14.057] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[    14.057] (--) NVIDIA(GPU-0): 
[    14.057] (--) NVIDIA(GPU-0): DFP-1: disconnected
[    14.057] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[    14.057] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[    14.057] (--) NVIDIA(GPU-0): 
[    14.058] (II) NVIDIA(G0): Validated MetaModes:
[    14.058] (II) NVIDIA(G0):     "NULL"
[    14.058] (II) NVIDIA(G0): Virtual screen size determined to be 640 x 480
[    14.058] (WW) NVIDIA(G0): Unable to get display device for DPI computation.
[    14.058] (==) NVIDIA(G0): DPI set to (75, 75); computed from built-in default
[    14.058] (II) UnloadModule: "modesetting"
[    14.058] (II) Unloading modesetting
[    14.058] (II) UnloadModule: "fbdev"
[    14.058] (II) Unloading fbdev
[    14.058] (II) UnloadSubModule: "fbdevhw"
[    14.058] (II) Unloading fbdevhw
[    14.058] (II) UnloadModule: "vesa"
[    14.058] (II) Unloading vesa
[    14.058] (II) AMDGPU(0): [DRI2] Setup complete
[    14.058] (II) AMDGPU(0): [DRI2]   DRI driver: radeonsi
[    14.058] (II) AMDGPU(0): [DRI2]   VDPAU driver: radeonsi
[    14.071] (II) AMDGPU(0): Front buffer pitch: 23040 bytes
[    14.071] (II) AMDGPU(0): SYNC extension fences enabled
[    14.071] (II) AMDGPU(0): Present extension enabled
[    14.071] (==) AMDGPU(0): DRI3 enabled
[    14.071] (==) AMDGPU(0): Backing store enabled
[    14.071] (II) AMDGPU(0): Direct rendering enabled
[    14.084] (II) AMDGPU(0): Use GLAMOR acceleration.
[    14.085] (II) AMDGPU(0): Acceleration enabled
[    14.085] (==) AMDGPU(0): DPMS enabled
[    14.085] (==) AMDGPU(0): Silken mouse enabled
[    14.085] (II) AMDGPU(0): Set up textured video (glamor)
[    14.085] (II) NVIDIA: Reserving 24576.00 MB of virtual memory for indirect memory
[    14.085] (II) NVIDIA:     access.
[    14.093] (II) NVIDIA(G0): ACPI: failed to connect to the ACPI event daemon; the daemon
[    14.093] (II) NVIDIA(G0):     may not be running or the "AcpidSocketPath" X
[    14.093] (II) NVIDIA(G0):     configuration option may not be set correctly.  When the
[    14.093] (II) NVIDIA(G0):     ACPI event daemon is available, the NVIDIA X driver will
[    14.093] (II) NVIDIA(G0):     try to use it to receive ACPI event notifications.  For
[    14.093] (II) NVIDIA(G0):     details, please see the "ConnectToAcpid" and
[    14.093] (II) NVIDIA(G0):     "AcpidSocketPath" X configuration options in Appendix B: X
[    14.093] (II) NVIDIA(G0):     Config Options in the README.
[    14.105] (II) NVIDIA(G0): Setting mode "NULL"
[    14.113] (==) NVIDIA(G0): Disabling shared memory pixmaps
[    14.113] (==) NVIDIA(G0): Backing store enabled
[    14.113] (==) NVIDIA(G0): Silken mouse enabled
[    14.113] (==) NVIDIA(G0): DPMS enabled
[    14.113] (II) Loading sub module "dri2"
[    14.113] (II) LoadModule: "dri2"
[    14.113] (II) Module "dri2" already built-in
[    14.113] (II) NVIDIA(G0): [DRI2] Setup complete
[    14.113] (II) NVIDIA(G0): [DRI2]   VDPAU driver: nvidia
[    14.113] (II) Initializing extension Generic Event Extension
[    14.113] (II) Initializing extension SHAPE
[    14.114] (II) Initializing extension MIT-SHM
[    14.114] (II) Initializing extension XInputExtension
[    14.114] (II) Initializing extension XTEST
[    14.114] (II) Initializing extension BIG-REQUESTS
[    14.114] (II) Initializing extension SYNC
[    14.114] (II) Initializing extension XKEYBOARD
[    14.114] (II) Initializing extension XC-MISC
[    14.114] (II) Initializing extension SECURITY
[    14.114] (II) Initializing extension XFIXES
[    14.114] (II) Initializing extension RENDER
[    14.114] (II) Initializing extension RANDR
[    14.114] (II) Initializing extension COMPOSITE
[    14.114] (II) Initializing extension DAMAGE
[    14.114] (II) Initializing extension MIT-SCREEN-SAVER
[    14.114] (II) Initializing extension DOUBLE-BUFFER
[    14.114] (II) Initializing extension RECORD
[    14.114] (II) Initializing extension DPMS
[    14.115] (II) Initializing extension Present
[    14.115] (II) Initializing extension DRI3
[    14.115] (II) Initializing extension X-Resource
[    14.115] (II) Initializing extension XVideo
[    14.115] (II) Initializing extension XVideo-MotionCompensation
[    14.115] (II) Initializing extension GLX
[    14.115] (II) Initializing extension GLX
[    14.115] (II) Indirect GLX disabled.
[    14.118] (II) AIGLX: Loaded and initialized radeonsi
[    14.118] (II) GLX: Initialized DRI2 GL provider for screen 0
[    14.118] (II) Initializing extension XFree86-VidModeExtension
[    14.118] (II) Initializing extension XFree86-DGA
[    14.118] (II) Initializing extension XFree86-DRI
[    14.118] (II) Initializing extension DRI2
[    14.118] (II) Initializing extension NV-GLX
[    14.118] (II) Initializing extension NV-CONTROL
[    14.118] (II) AMDGPU(0): Setting screen physical size to 1524 x 571
[    14.784] (II) config/udev: Adding input device Asus Wireless Radio Control (/dev/input/event4)
[    14.784] (**) Asus Wireless Radio Control: Applying InputClass "libinput keyboard catchall"
[    14.784] (II) LoadModule: "libinput"
[    14.784] (II) Loading /usr/lib/xorg/modules/input/libinput_drv.so
[    14.785] (II) Module libinput: vendor="X.Org Foundation"
[    14.785] 	compiled for 1.21.1.3, module version = 1.2.1
[    14.785] 	Module class: X.Org XInput Driver
[    14.785] 	ABI class: X.Org XInput driver, version 24.4
[    14.785] (II) Using input driver 'libinput' for 'Asus Wireless Radio Control'
[    14.786] (II) systemd-logind: got fd for /dev/input/event4 13:68 fd 49 paused 0
[    14.786] (**) Asus Wireless Radio Control: always reports core events
[    14.786] (**) Option "Device" "/dev/input/event4"
[    14.786] (II) event4  - Asus Wireless Radio Control: is tagged by udev as: Keyboard
[    14.787] (II) event4  - Asus Wireless Radio Control: device is a keyboard
[    14.787] (II) event4  - Asus Wireless Radio Control: device removed
[    14.787] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/ATK4002:00/input/input4/event4"
[    14.787] (II) XINPUT: Adding extended input device "Asus Wireless Radio Control" (type: KEYBOARD, id 6)
[    14.787] (II) event4  - Asus Wireless Radio Control: is tagged by udev as: Keyboard
[    14.787] (II) event4  - Asus Wireless Radio Control: device is a keyboard
[    14.787] (II) config/udev: Adding input device Video Bus (/dev/input/event5)
[    14.787] (**) Video Bus: Applying InputClass "libinput keyboard catchall"
[    14.787] (II) Using input driver 'libinput' for 'Video Bus'
[    14.788] (II) systemd-logind: got fd for /dev/input/event5 13:69 fd 52 paused 0
[    14.788] (**) Video Bus: always reports core events
[    14.788] (**) Option "Device" "/dev/input/event5"
[    14.788] (II) event5  - Video Bus: is tagged by udev as: Keyboard
[    14.788] (II) event5  - Video Bus: device is a keyboard
[    14.788] (II) event5  - Video Bus: device removed
[    14.788] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/PNP0A08:00/device:01/LNXVIDEO:00/input/input5/event5"
[    14.788] (II) XINPUT: Adding extended input device "Video Bus" (type: KEYBOARD, id 7)
[    14.789] (II) event5  - Video Bus: is tagged by udev as: Keyboard
[    14.789] (II) event5  - Video Bus: device is a keyboard
[    14.789] (II) config/udev: Adding input device Video Bus (/dev/input/event6)
[    14.789] (**) Video Bus: Applying InputClass "libinput keyboard catchall"
[    14.789] (II) Using input driver 'libinput' for 'Video Bus'
[    14.790] (II) systemd-logind: got fd for /dev/input/event6 13:70 fd 53 paused 0
[    14.790] (**) Video Bus: always reports core events
[    14.790] (**) Option "Device" "/dev/input/event6"
[    14.790] (II) event6  - Video Bus: is tagged by udev as: Keyboard
[    14.790] (II) event6  - Video Bus: device is a keyboard
[    14.790] (II) event6  - Video Bus: device removed
[    14.790] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/PNP0A08:00/device:0f/LNXVIDEO:01/input/input6/event6"
[    14.790] (II) XINPUT: Adding extended input device "Video Bus" (type: KEYBOARD, id 8)
[    14.791] (II) event6  - Video Bus: is tagged by udev as: Keyboard
[    14.791] (II) event6  - Video Bus: device is a keyboard
[    14.791] (II) config/udev: Adding input device Power Button (/dev/input/event0)
[    14.791] (**) Power Button: Applying InputClass "libinput keyboard catchall"
[    14.791] (II) Using input driver 'libinput' for 'Power Button'
[    14.791] (II) systemd-logind: got fd for /dev/input/event0 13:64 fd 54 paused 0
[    14.791] (**) Power Button: always reports core events
[    14.791] (**) Option "Device" "/dev/input/event0"
[    14.791] (II) event0  - Power Button: is tagged by udev as: Keyboard
[    14.792] (II) event0  - Power Button: device is a keyboard
[    14.792] (II) event0  - Power Button: device removed
[    14.792] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/PNP0C0C:00/input/input0/event0"
[    14.792] (II) XINPUT: Adding extended input device "Power Button" (type: KEYBOARD, id 9)
[    14.792] (II) event0  - Power Button: is tagged by udev as: Keyboard
[    14.792] (II) event0  - Power Button: device is a keyboard
[    14.792] (II) config/udev: Adding input device Lid Switch (/dev/input/event2)
[    14.792] (II) No input driver specified, ignoring this device.
[    14.792] (II) This device may have been added with another device file.
[    14.792] (II) config/udev: Adding input device Sleep Button (/dev/input/event1)
[    14.792] (**) Sleep Button: Applying InputClass "libinput keyboard catchall"
[    14.792] (II) Using input driver 'libinput' for 'Sleep Button'
[    14.793] (II) systemd-logind: got fd for /dev/input/event1 13:65 fd 55 paused 0
[    14.793] (**) Sleep Button: always reports core events
[    14.793] (**) Option "Device" "/dev/input/event1"
[    14.793] (II) event1  - Sleep Button: is tagged by udev as: Keyboard
[    14.793] (II) event1  - Sleep Button: device is a keyboard
[    14.793] (II) event1  - Sleep Button: device removed
[    14.793] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/PNP0C0E:00/input/input1/event1"
[    14.793] (II) XINPUT: Adding extended input device "Sleep Button" (type: KEYBOARD, id 10)
[    14.794] (II) event1  - Sleep Button: is tagged by udev as: Keyboard
[    14.794] (II) event1  - Sleep Button: device is a keyboard
[    14.794] (II) config/udev: Adding input device HDA NVidia HDMI/DP,pcm=3 (/dev/input/event15)
[    14.794] (II) No input driver specified, ignoring this device.
[    14.794] (II) This device may have been added with another device file.
[    14.794] (II) config/udev: Adding input device HDA NVidia HDMI/DP,pcm=7 (/dev/input/event16)
[    14.794] (II) No input driver specified, ignoring this device.
[    14.794] (II) This device may have been added with another device file.
[    14.794] (II) config/udev: Adding input device HDA NVidia HDMI/DP,pcm=8 (/dev/input/event17)
[    14.794] (II) No input driver specified, ignoring this device.
[    14.794] (II) This device may have been added with another device file.
[    14.794] (II) config/udev: Adding input device HDA NVidia HDMI/DP,pcm=9 (/dev/input/event18)
[    14.794] (II) No input driver specified, ignoring this device.
[    14.794] (II) This device may have been added with another device file.
[    14.795] (II) config/udev: Adding input device HD-Audio Generic HDMI/DP,pcm=3 (/dev/input/event14)
[    14.795] (II) No input driver specified, ignoring this device.
[    14.795] (II) This device may have been added with another device file.
[    14.795] (II) config/udev: Adding input device Logitech Wireless Keyboard PID:4023 (/dev/input/event19)
[    14.795] (**) Logitech Wireless Keyboard PID:4023: Applying InputClass "libinput keyboard catchall"
[    14.795] (II) Using input driver 'libinput' for 'Logitech Wireless Keyboard PID:4023'
[    14.795] (II) systemd-logind: got fd for /dev/input/event19 13:83 fd 56 paused 0
[    14.795] (**) Logitech Wireless Keyboard PID:4023: always reports core events
[    14.795] (**) Option "Device" "/dev/input/event19"
[    14.796] (II) event19 - Logitech Wireless Keyboard PID:4023: is tagged by udev as: Keyboard
[    14.796] (II) event19 - Logitech Wireless Keyboard PID:4023: device is a keyboard
[    14.796] (II) event19 - Logitech Wireless Keyboard PID:4023: device removed
[    14.796] (II) libinput: Logitech Wireless Keyboard PID:4023: needs a virtual subdevice
[    14.796] (**) Option "config_info" "udev:/sys/devices/pci0000:00/0000:00:08.1/0000:06:00.3/usb1/1-2/1-2:1.1/0003:046D:C534.0002/0003:046D:4023.0004/input/input35/event19"
[    14.796] (II) XINPUT: Adding extended input device "Logitech Wireless Keyboard PID:4023" (type: MOUSE, id 11)
[    14.796] (**) Option "AccelerationScheme" "none"
[    14.796] (**) Logitech Wireless Keyboard PID:4023: (accel) selected scheme none/0
[    14.796] (**) Logitech Wireless Keyboard PID:4023: (accel) acceleration factor: 2.000
[    14.796] (**) Logitech Wireless Keyboard PID:4023: (accel) acceleration threshold: 4
[    14.797] (II) event19 - Logitech Wireless Keyboard PID:4023: is tagged by udev as: Keyboard
[    14.797] (II) event19 - Logitech Wireless Keyboard PID:4023: device is a keyboard
[    14.797] (II) config/udev: Adding input device Logitech Wireless Mouse (/dev/input/event13)
[    14.797] (**) Logitech Wireless Mouse: Applying InputClass "libinput pointer catchall"
[    14.797] (II) Using input driver 'libinput' for 'Logitech Wireless Mouse'
[    14.798] (II) systemd-logind: got fd for /dev/input/event13 13:77 fd 57 paused 0
[    14.798] (**) Logitech Wireless Mouse: always reports core events
[    14.798] (**) Option "Device" "/dev/input/event13"
[    14.798] (II) event13 - Logitech Wireless Mouse: is tagged by udev as: Mouse
[    14.798] (II) event13 - Logitech Wireless Mouse: device is a pointer
[    14.798] (II) event13 - Logitech Wireless Mouse: device removed
[    14.798] (**) Option "config_info" "udev:/sys/devices/pci0000:00/0000:00:08.1/0000:06:00.3/usb1/1-2/1-2:1.1/0003:046D:C534.0002/0003:046D:4058.0005/input/input36/event13"
[    14.798] (II) XINPUT: Adding extended input device "Logitech Wireless Mouse" (type: MOUSE, id 12)
[    14.799] (**) Option "AccelerationScheme" "none"
[    14.799] (**) Logitech Wireless Mouse: (accel) selected scheme none/0
[    14.799] (**) Logitech Wireless Mouse: (accel) acceleration factor: 2.000
[    14.799] (**) Logitech Wireless Mouse: (accel) acceleration threshold: 4
[    14.799] (II) event13 - Logitech Wireless Mouse: is tagged by udev as: Mouse
[    14.799] (II) event13 - Logitech Wireless Mouse: device is a pointer
[    14.800] (II) config/udev: Adding input device Logitech Wireless Mouse (/dev/input/mouse2)
[    14.800] (II) No input driver specified, ignoring this device.
[    14.800] (II) This device may have been added with another device file.
[    14.800] (II) config/udev: Adding input device USB2.0 HD UVC WebCam: USB2.0 HD (/dev/input/event9)
[    14.800] (**) USB2.0 HD UVC WebCam: USB2.0 HD: Applying InputClass "libinput keyboard catchall"
[    14.800] (II) Using input driver 'libinput' for 'USB2.0 HD UVC WebCam: USB2.0 HD'
[    14.800] (II) systemd-logind: got fd for /dev/input/event9 13:73 fd 58 paused 0
[    14.800] (**) USB2.0 HD UVC WebCam: USB2.0 HD: always reports core events
[    14.800] (**) Option "Device" "/dev/input/event9"
[    14.801] (II) event9  - USB2.0 HD UVC WebCam: USB2.0 HD: is tagged by udev as: Keyboard
[    14.801] (II) event9  - USB2.0 HD UVC WebCam: USB2.0 HD: device is a keyboard
[    14.801] (II) event9  - USB2.0 HD UVC WebCam: USB2.0 HD: device removed
[    14.801] (**) Option "config_info" "udev:/sys/devices/pci0000:00/0000:00:08.1/0000:06:00.3/usb1/1-4/1-4:1.0/input/input22/event9"
[    14.801] (II) XINPUT: Adding extended input device "USB2.0 HD UVC WebCam: USB2.0 HD" (type: KEYBOARD, id 13)
[    14.801] (II) event9  - USB2.0 HD UVC WebCam: USB2.0 HD: is tagged by udev as: Keyboard
[    14.801] (II) event9  - USB2.0 HD UVC WebCam: USB2.0 HD: device is a keyboard
[    14.802] (II) config/udev: Adding input device HD-Audio Generic Headphone (/dev/input/event12)
[    14.802] (II) No input driver specified, ignoring this device.
[    14.802] (II) This device may have been added with another device file.
[    14.802] (II) config/udev: Adding input device ELAN1203:00 04F3:307A Mouse (/dev/input/event10)
[    14.802] (**) ELAN1203:00 04F3:307A Mouse: Applying InputClass "libinput pointer catchall"
[    14.802] (II) Using input driver 'libinput' for 'ELAN1203:00 04F3:307A Mouse'
[    14.802] (II) systemd-logind: got fd for /dev/input/event10 13:74 fd 59 paused 0
[    14.802] (**) ELAN1203:00 04F3:307A Mouse: always reports core events
[    14.802] (**) Option "Device" "/dev/input/event10"
[    14.803] (II) event10 - ELAN1203:00 04F3:307A Mouse: is tagged by udev as: Mouse Pointingstick
[    14.803] (II) event10 - ELAN1203:00 04F3:307A Mouse: device is a pointer
[    14.803] (II) event10 - ELAN1203:00 04F3:307A Mouse: device removed
[    14.803] (**) Option "config_info" "udev:/sys/devices/platform/AMDI0010:03/i2c-0/i2c-ELAN1203:00/0018:04F3:307A.0003/input/input23/event10"
[    14.803] (II) XINPUT: Adding extended input device "ELAN1203:00 04F3:307A Mouse" (type: MOUSE, id 14)
[    14.803] (**) Option "AccelerationScheme" "none"
[    14.803] (**) ELAN1203:00 04F3:307A Mouse: (accel) selected scheme none/0
[    14.803] (**) ELAN1203:00 04F3:307A Mouse: (accel) acceleration factor: 2.000
[    14.803] (**) ELAN1203:00 04F3:307A Mouse: (accel) acceleration threshold: 4
[    14.804] (II) event10 - ELAN1203:00 04F3:307A Mouse: is tagged by udev as: Mouse Pointingstick
[    14.804] (II) event10 - ELAN1203:00 04F3:307A Mouse: device is a pointer
[    14.804] (II) config/udev: Adding input device ELAN1203:00 04F3:307A Mouse (/dev/input/mouse0)
[    14.804] (II) No input driver specified, ignoring this device.
[    14.804] (II) This device may have been added with another device file.
[    14.805] (II) config/udev: Adding input device ELAN1203:00 04F3:307A Touchpad (/dev/input/event11)
[    14.805] (**) ELAN1203:00 04F3:307A Touchpad: Applying InputClass "libinput touchpad catchall"
[    14.805] (II) Using input driver 'libinput' for 'ELAN1203:00 04F3:307A Touchpad'
[    14.805] (II) systemd-logind: got fd for /dev/input/event11 13:75 fd 60 paused 0
[    14.805] (**) ELAN1203:00 04F3:307A Touchpad: always reports core events
[    14.805] (**) Option "Device" "/dev/input/event11"
[    14.805] (II) event11 - ELAN1203:00 04F3:307A Touchpad: is tagged by udev as: Touchpad
[    14.806] (II) event11 - ELAN1203:00 04F3:307A Touchpad: device is a touchpad
[    14.806] (II) event11 - ELAN1203:00 04F3:307A Touchpad: device removed
[    14.806] (**) Option "config_info" "udev:/sys/devices/platform/AMDI0010:03/i2c-0/i2c-ELAN1203:00/0018:04F3:307A.0003/input/input24/event11"
[    14.806] (II) XINPUT: Adding extended input device "ELAN1203:00 04F3:307A Touchpad" (type: TOUCHPAD, id 15)
[    14.807] (**) Option "AccelerationScheme" "none"
[    14.807] (**) ELAN1203:00 04F3:307A Touchpad: (accel) selected scheme none/0
[    14.807] (**) ELAN1203:00 04F3:307A Touchpad: (accel) acceleration factor: 2.000
[    14.807] (**) ELAN1203:00 04F3:307A Touchpad: (accel) acceleration threshold: 4
[    14.807] (II) event11 - ELAN1203:00 04F3:307A Touchpad: is tagged by udev as: Touchpad
[    14.808] (II) event11 - ELAN1203:00 04F3:307A Touchpad: device is a touchpad
[    14.808] (II) config/udev: Adding input device ELAN1203:00 04F3:307A Touchpad (/dev/input/mouse1)
[    14.808] (II) No input driver specified, ignoring this device.
[    14.808] (II) This device may have been added with another device file.
[    14.808] (II) config/udev: Adding input device Asus WMI hotkeys (/dev/input/event8)
[    14.808] (**) Asus WMI hotkeys: Applying InputClass "libinput keyboard catchall"
[    14.808] (II) Using input driver 'libinput' for 'Asus WMI hotkeys'
[    14.808] (II) systemd-logind: got fd for /dev/input/event8 13:72 fd 61 paused 0
[    14.808] (**) Asus WMI hotkeys: always reports core events
[    14.808] (**) Option "Device" "/dev/input/event8"
[    14.809] (II) event8  - Asus WMI hotkeys: is tagged by udev as: Keyboard
[    14.809] (II) event8  - Asus WMI hotkeys: device is a keyboard
[    14.809] (II) event8  - Asus WMI hotkeys: device removed
[    14.809] (**) Option "config_info" "udev:/sys/devices/platform/asus-nb-wmi/input/input21/event8"
[    14.809] (II) XINPUT: Adding extended input device "Asus WMI hotkeys" (type: KEYBOARD, id 16)
[    14.809] (II) event8  - Asus WMI hotkeys: is tagged by udev as: Keyboard
[    14.809] (II) event8  - Asus WMI hotkeys: device is a keyboard
[    14.810] (II) config/udev: Adding input device AT Translated Set 2 keyboard (/dev/input/event3)
[    14.810] (**) AT Translated Set 2 keyboard: Applying InputClass "libinput keyboard catchall"
[    14.810] (II) Using input driver 'libinput' for 'AT Translated Set 2 keyboard'
[    14.810] (II) systemd-logind: got fd for /dev/input/event3 13:67 fd 62 paused 0
[    14.810] (**) AT Translated Set 2 keyboard: always reports core events
[    14.810] (**) Option "Device" "/dev/input/event3"
[    14.810] (II) event3  - AT Translated Set 2 keyboard: is tagged by udev as: Keyboard
[    14.810] (II) event3  - AT Translated Set 2 keyboard: device is a keyboard
[    14.811] (II) event3  - AT Translated Set 2 keyboard: device removed
[    14.811] (**) Option "config_info" "udev:/sys/devices/platform/i8042/serio0/input/input3/event3"
[    14.811] (II) XINPUT: Adding extended input device "AT Translated Set 2 keyboard" (type: KEYBOARD, id 17)
[    14.812] (II) event3  - AT Translated Set 2 keyboard: is tagged by udev as: Keyboard
[    14.812] (II) event3  - AT Translated Set 2 keyboard: device is a keyboard
[    14.812] (II) config/udev: Adding input device PC Speaker (/dev/input/event7)
[    14.812] (II) No input driver specified, ignoring this device.
[    14.812] (II) This device may have been added with another device file.
[    14.819] (**) Logitech Wireless Keyboard PID:4023: Applying InputClass "libinput keyboard catchall"
[    14.820] (II) Using input driver 'libinput' for 'Logitech Wireless Keyboard PID:4023'
[    14.820] (II) systemd-logind: returning pre-existing fd for /dev/input/event19 13:83
[    14.820] (**) Logitech Wireless Keyboard PID:4023: always reports core events
[    14.820] (**) Option "Device" "/dev/input/event19"
[    14.820] (II) libinput: Logitech Wireless Keyboard PID:4023: is a virtual subdevice
[    14.820] (**) Option "config_info" "udev:/sys/devices/pci0000:00/0000:00:08.1/0000:06:00.3/usb1/1-2/1-2:1.1/0003:046D:C534.0002/0003:046D:4023.0004/input/input35/event19"
[    14.820] (II) XINPUT: Adding extended input device "Logitech Wireless Keyboard PID:4023" (type: KEYBOARD, id 18)
[    15.113] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[    15.113] (II) AMDGPU(0): Using EDID range info for horizontal sync
[    15.113] (II) AMDGPU(0): Using EDID range info for vertical refresh
[    15.113] (II) AMDGPU(0): Printing DDC gathered Modelines:
[    15.113] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[    15.113] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[    15.114] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[    15.116] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[    15.116] (II) AMDGPU(0): Using hsync ranges from config file
[    15.116] (II) AMDGPU(0): Using vrefresh ranges from config file
[    15.116] (II) AMDGPU(0): Printing DDC gathered Modelines:
[    15.116] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[    15.116] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[    15.117] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[    15.117] (--) NVIDIA(GPU-0): DFP-0: disconnected
[    15.117] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[    15.117] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[    15.117] (--) NVIDIA(GPU-0): 
[    15.117] (--) NVIDIA(GPU-0): DFP-1: disconnected
[    15.117] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[    15.117] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[    15.117] (--) NVIDIA(GPU-0): 
[    15.865] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[    15.865] (II) AMDGPU(0): Using hsync ranges from config file
[    15.865] (II) AMDGPU(0): Using vrefresh ranges from config file
[    15.865] (II) AMDGPU(0): Printing DDC gathered Modelines:
[    15.865] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[    15.865] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[    15.867] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[    15.869] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[    15.869] (II) AMDGPU(0): Using hsync ranges from config file
[    15.869] (II) AMDGPU(0): Using vrefresh ranges from config file
[    15.869] (II) AMDGPU(0): Printing DDC gathered Modelines:
[    15.869] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[    15.869] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[    15.870] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[    15.870] (--) NVIDIA(GPU-0): DFP-0: disconnected
[    15.870] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[    15.870] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[    15.870] (--) NVIDIA(GPU-0): 
[    15.871] (--) NVIDIA(GPU-0): DFP-1: disconnected
[    15.871] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[    15.871] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[    15.871] (--) NVIDIA(GPU-0): 
[    16.603] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[    16.603] (II) AMDGPU(0): Using hsync ranges from config file
[    16.603] (II) AMDGPU(0): Using vrefresh ranges from config file
[    16.603] (II) AMDGPU(0): Printing DDC gathered Modelines:
[    16.603] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[    16.603] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[    16.605] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[    16.607] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[    16.607] (II) AMDGPU(0): Using hsync ranges from config file
[    16.607] (II) AMDGPU(0): Using vrefresh ranges from config file
[    16.607] (II) AMDGPU(0): Printing DDC gathered Modelines:
[    16.607] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[    16.607] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[    16.608] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[    16.608] (--) NVIDIA(GPU-0): DFP-0: disconnected
[    16.608] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[    16.608] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[    16.608] (--) NVIDIA(GPU-0): 
[    16.608] (--) NVIDIA(GPU-0): DFP-1: disconnected
[    16.608] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[    16.608] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[    16.608] (--) NVIDIA(GPU-0): 
[    16.950] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[    16.950] (II) AMDGPU(0): Using hsync ranges from config file
[    16.950] (II) AMDGPU(0): Using vrefresh ranges from config file
[    16.950] (II) AMDGPU(0): Printing DDC gathered Modelines:
[    16.950] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[    16.950] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[    16.951] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[    16.953] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[    16.953] (II) AMDGPU(0): Using hsync ranges from config file
[    16.953] (II) AMDGPU(0): Using vrefresh ranges from config file
[    16.953] (II) AMDGPU(0): Printing DDC gathered Modelines:
[    16.953] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[    16.953] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[    16.954] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[    16.954] (--) NVIDIA(GPU-0): DFP-0: disconnected
[    16.954] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[    16.954] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[    16.954] (--) NVIDIA(GPU-0): 
[    16.954] (--) NVIDIA(GPU-0): DFP-1: disconnected
[    16.954] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[    16.954] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[    16.954] (--) NVIDIA(GPU-0): 
[    26.336] (**) Option "fd" "49"
[    26.336] (II) event4  - Asus Wireless Radio Control: device removed
[    26.336] (**) Option "fd" "52"
[    26.336] (II) event5  - Video Bus: device removed
[    26.336] (**) Option "fd" "53"
[    26.336] (II) event6  - Video Bus: device removed
[    26.336] (**) Option "fd" "54"
[    26.336] (II) event0  - Power Button: device removed
[    26.336] (**) Option "fd" "55"
[    26.336] (II) event1  - Sleep Button: device removed
[    26.337] (**) Option "fd" "56"
[    26.337] (**) Option "fd" "57"
[    26.337] (II) event13 - Logitech Wireless Mouse: device removed
[    26.337] (**) Option "fd" "58"
[    26.337] (II) event9  - USB2.0 HD UVC WebCam: USB2.0 HD: device removed
[    26.337] (**) Option "fd" "59"
[    26.337] (II) event10 - ELAN1203:00 04F3:307A Mouse: device removed
[    26.337] (**) Option "fd" "60"
[    26.337] (II) event11 - ELAN1203:00 04F3:307A Touchpad: device removed
[    26.337] (**) Option "fd" "61"
[    26.337] (II) event8  - Asus WMI hotkeys: device removed
[    26.337] (**) Option "fd" "62"
[    26.337] (II) event3  - AT Translated Set 2 keyboard: device removed
[    26.337] (**) Option "fd" "56"
[    26.337] (II) event19 - Logitech Wireless Keyboard PID:4023: device removed
[    26.338] (II) UnloadModule: "libinput"
[    26.338] (II) systemd-logind: not releasing fd for 13:83, still in use
[    26.338] (II) UnloadModule: "libinput"
[    26.338] (II) systemd-logind: releasing fd for 13:67
[    26.401] (II) UnloadModule: "libinput"
[    26.401] (II) systemd-logind: releasing fd for 13:72
[    26.481] (II) UnloadModule: "libinput"
[    26.481] (II) systemd-logind: releasing fd for 13:75
[    26.541] (II) UnloadModule: "libinput"
[    26.541] (II) systemd-logind: releasing fd for 13:74
[    26.601] (II) UnloadModule: "libinput"
[    26.601] (II) systemd-logind: releasing fd for 13:73
[    26.664] (II) UnloadModule: "libinput"
[    26.664] (II) systemd-logind: releasing fd for 13:77
[    26.728] (II) UnloadModule: "libinput"
[    26.728] (II) systemd-logind: releasing fd for 13:83
[    26.751] (II) UnloadModule: "libinput"
[    26.751] (II) systemd-logind: releasing fd for 13:65
[    26.785] (II) UnloadModule: "libinput"
[    26.785] (II) systemd-logind: releasing fd for 13:64
[    26.818] (II) UnloadModule: "libinput"
[    26.818] (II) systemd-logind: releasing fd for 13:70
[    26.851] (II) UnloadModule: "libinput"
[    26.851] (II) systemd-logind: releasing fd for 13:69
[    26.885] (II) UnloadModule: "libinput"
[    26.885] (II) systemd-logind: releasing fd for 13:68
[    26.961] (II) NVIDIA(GPU-0): Deleting GPU-0
[    26.967] (WW) xf86CloseConsole: KDSETMODE failed: Input/output error
[    26.967] (WW) xf86CloseConsole: VT_GETMODE failed: Input/output error
[    27.138] (II) Server terminated successfully (0). Closing log file.

____________________________________________

*** /var/log/Xorg.1.log.old
*** ls: -rw-r--r-- 1 root nomade 134349 2022-10-14 23:34:03.181360384 -0300 /var/log/Xorg.1.log.old
[    12.050] _XSERVTransSocketUNIXCreateListener: ...SocketCreateListener() failed
[    12.050] _XSERVTransMakeAllCOTSServerListeners: server already running
[    12.050] (--) Log file renamed from "/var/log/Xorg.pid-1358.log" to "/var/log/Xorg.1.log"
[    12.050] 
X.Org X Server 1.21.1.4
X Protocol Version 11, Revision 0
[    12.050] Current Operating System: Linux nomade007 5.19.12-arch1-1 #1 SMP PREEMPT_DYNAMIC Wed, 28 Sep 2022 13:21:25 +0000 x86_64
[    12.050] Kernel command line: initrd=\amd-ucode.img initrd=\initramfs-linux.img root=PARTUUID=f407dfcd-5b75-c540-99c7-811fac3135b7 rw
[    12.050]  
[    12.050] Current version of pixman: 0.40.0
[    12.050] 	Before reporting problems, check http://wiki.x.org
	to make sure that you have the latest version.
[    12.050] Markers: (--) probed, (**) from config file, (==) default setting,
	(++) from command line, (!!) notice, (II) informational,
	(WW) warning, (EE) error, (NI) not implemented, (??) unknown.
[    12.050] (==) Log file: "/var/log/Xorg.1.log", Time: Fri Oct 14 13:10:36 2022
[    12.050] (==) Using system config directory "/usr/share/X11/xorg.conf.d"
[    12.050] (==) No Layout section.  Using the first Screen section.
[    12.050] (==) No screen section available. Using defaults.
[    12.050] (**) |-->Screen "Default Screen Section" (0)
[    12.050] (**) |   |-->Monitor "<default monitor>"
[    12.050] (==) No monitor specified for screen "Default Screen Section".
	Using a default monitor configuration.
[    12.050] (==) Automatically adding devices
[    12.050] (==) Automatically enabling devices
[    12.050] (==) Automatically adding GPU devices
[    12.050] (==) Automatically binding GPU devices
[    12.050] (==) Max clients allowed: 256, resource mask: 0x1fffff
[    12.050] (WW) The directory "/usr/share/fonts/misc" does not exist.
[    12.050] 	Entry deleted from font path.
[    12.050] (WW) The directory "/usr/share/fonts/OTF" does not exist.
[    12.050] 	Entry deleted from font path.
[    12.050] (WW) The directory "/usr/share/fonts/Type1" does not exist.
[    12.050] 	Entry deleted from font path.
[    12.050] (==) FontPath set to:
	/usr/share/fonts/TTF,
	/usr/share/fonts/100dpi,
	/usr/share/fonts/75dpi
[    12.050] (==) ModulePath set to "/usr/lib/xorg/modules"
[    12.050] (II) The server relies on udev to provide the list of input devices.
	If no devices become available, reconfigure udev or disable AutoAddDevices.
[    12.050] (II) Module ABI versions:
[    12.050] 	X.Org ANSI C Emulation: 0.4
[    12.050] 	X.Org Video Driver: 25.2
[    12.050] 	X.Org XInput driver : 24.4
[    12.050] 	X.Org Server Extension : 10.0
[    12.051] (++) using VT number 2

[    12.052] (II) systemd-logind: took control of session /org/freedesktop/login1/session/_33
[    12.052] (II) xfree86: Adding drm device (/dev/dri/card1)
[    12.052] (II) Platform probe for /sys/devices/pci0000:00/0000:00:01.1/0000:01:00.0/drm/card1
[    12.052] (II) systemd-logind: got fd for /dev/dri/card1 226:1 fd 15 paused 0
[    12.052] (II) xfree86: Adding drm device (/dev/dri/card0)
[    12.052] (II) Platform probe for /sys/devices/pci0000:00/0000:00:08.1/0000:06:00.0/drm/card0
[    12.053] (II) systemd-logind: got fd for /dev/dri/card0 226:0 fd 16 paused 0
[    12.054] (**) OutputClass "nvidia" ModulePath extended to "/usr/lib/nvidia/xorg,/usr/lib/xorg/modules,/usr/lib/xorg/modules"
[    12.054] (--) PCI: (1@0:0:0) 10de:2520:1043:16a2 rev 161, Mem @ 0xfb000000/16777216, 0xfc00000000/8589934592, 0xfe00000000/33554432, I/O @ 0x0000f000/128, BIOS @ 0x????????/524288
[    12.054] (--) PCI:*(6@0:0:0) 1002:1638:1043:16a2 rev 197, Mem @ 0xfe10000000/268435456, 0xfe20000000/2097152, 0xfc500000/524288, I/O @ 0x0000d000/256
[    12.054] (WW) Open ACPI failed (/var/run/acpid.socket) (No such file or directory)
[    12.054] (II) LoadModule: "glx"
[    12.055] (II) Loading /usr/lib/xorg/modules/extensions/libglx.so
[    12.055] (II) Module glx: vendor="X.Org Foundation"
[    12.055] 	compiled for 1.21.1.4, module version = 1.0.0
[    12.055] 	ABI class: X.Org Server Extension, version 10.0
[    12.055] (II) Applying OutputClass "AMDgpu" to /dev/dri/card0
[    12.055] 	loading driver: amdgpu
[    12.055] (II) Applying OutputClass "nvidia" to /dev/dri/card1
[    12.055] 	loading driver: nvidia
[    12.055] (==) Matched amdgpu as autoconfigured driver 0
[    12.055] (==) Matched ati as autoconfigured driver 1
[    12.055] (==) Matched nvidia as autoconfigured driver 2
[    12.055] (==) Matched nouveau as autoconfigured driver 3
[    12.055] (==) Matched nv as autoconfigured driver 4
[    12.055] (==) Matched modesetting as autoconfigured driver 5
[    12.055] (==) Matched fbdev as autoconfigured driver 6
[    12.055] (==) Matched vesa as autoconfigured driver 7
[    12.055] (==) Assigned the driver to the xf86ConfigLayout
[    12.055] (II) LoadModule: "amdgpu"
[    12.055] (II) Loading /usr/lib/xorg/modules/drivers/amdgpu_drv.so
[    12.056] (II) Module amdgpu: vendor="X.Org Foundation"
[    12.056] 	compiled for 1.21.1.3, module version = 22.0.0
[    12.056] 	Module class: X.Org Video Driver
[    12.056] 	ABI class: X.Org Video Driver, version 25.2
[    12.056] (II) LoadModule: "ati"
[    12.056] (WW) Warning, couldn't open module ati
[    12.056] (EE) Failed to load module "ati" (module does not exist, 0)
[    12.056] (II) LoadModule: "nvidia"
[    12.056] (II) Loading /usr/lib/xorg/modules/drivers/nvidia_drv.so
[    12.056] (II) Module nvidia: vendor="NVIDIA Corporation"
[    12.056] 	compiled for 1.6.99.901, module version = 1.0.0
[    12.056] 	Module class: X.Org Video Driver
[    12.056] (II) LoadModule: "nouveau"
[    12.056] (WW) Warning, couldn't open module nouveau
[    12.056] (EE) Failed to load module "nouveau" (module does not exist, 0)
[    12.056] (II) LoadModule: "nv"
[    12.056] (WW) Warning, couldn't open module nv
[    12.056] (EE) Failed to load module "nv" (module does not exist, 0)
[    12.056] (II) LoadModule: "modesetting"
[    12.056] (II) Loading /usr/lib/xorg/modules/drivers/modesetting_drv.so
[    12.056] (II) Module modesetting: vendor="X.Org Foundation"
[    12.056] 	compiled for 1.21.1.4, module version = 1.21.1
[    12.056] 	Module class: X.Org Video Driver
[    12.056] 	ABI class: X.Org Video Driver, version 25.2
[    12.056] (II) LoadModule: "fbdev"
[    12.056] (II) Loading /usr/lib/xorg/modules/drivers/fbdev_drv.so
[    12.056] (II) Module fbdev: vendor="X.Org Foundation"
[    12.056] 	compiled for 1.21.1.1, module version = 0.5.0
[    12.056] 	Module class: X.Org Video Driver
[    12.056] 	ABI class: X.Org Video Driver, version 25.2
[    12.056] (II) LoadModule: "vesa"
[    12.056] (II) Loading /usr/lib/xorg/modules/drivers/vesa_drv.so
[    12.056] (II) Module vesa: vendor="X.Org Foundation"
[    12.056] 	compiled for 1.21.1.3, module version = 2.5.0
[    12.056] 	Module class: X.Org Video Driver
[    12.056] 	ABI class: X.Org Video Driver, version 25.2
[    12.056] (II) AMDGPU: Driver for AMD Radeon:
	All GPUs supported by the amdgpu kernel driver
[    12.056] (II) NVIDIA dlloader X Driver  515.76  Mon Sep 12 19:18:09 UTC 2022
[    12.056] (II) NVIDIA Unified Driver for all Supported NVIDIA GPUs
[    12.056] (II) modesetting: Driver for Modesetting Kernel Drivers: kms
[    12.056] (II) FBDEV: driver for framebuffer: fbdev
[    12.056] (II) VESA: driver for VESA chipsets: vesa
[    12.062] (WW) Falling back to old probe method for modesetting
[    12.062] (WW) Falling back to old probe method for fbdev
[    12.062] (II) Loading sub module "fbdevhw"
[    12.062] (II) LoadModule: "fbdevhw"
[    12.062] (II) Loading /usr/lib/xorg/modules/libfbdevhw.so
[    12.062] (II) Module fbdevhw: vendor="X.Org Foundation"
[    12.062] 	compiled for 1.21.1.4, module version = 0.0.2
[    12.062] 	ABI class: X.Org Video Driver, version 25.2
[    12.062] (II) systemd-logind: releasing fd for 226:1
[    12.062] (II) Loading sub module "fb"
[    12.062] (II) LoadModule: "fb"
[    12.062] (II) Module "fb" already built-in
[    12.062] (II) Loading sub module "wfb"
[    12.062] (II) LoadModule: "wfb"
[    12.062] (II) Loading /usr/lib/xorg/modules/libwfb.so
[    12.062] (II) Module wfb: vendor="X.Org Foundation"
[    12.062] 	compiled for 1.21.1.4, module version = 1.0.0
[    12.062] 	ABI class: X.Org ANSI C Emulation, version 0.4
[    12.062] (II) Loading sub module "ramdac"
[    12.062] (II) LoadModule: "ramdac"
[    12.062] (II) Module "ramdac" already built-in
[    12.063] (II) AMDGPU(0): Creating default Display subsection in Screen section
	"Default Screen Section" for depth/fbbpp 24/32
[    12.063] (==) AMDGPU(0): Depth 24, (--) framebuffer bpp 32
[    12.063] (II) AMDGPU(0): Pixel depth = 24 bits stored in 4 bytes (32 bpp pixmaps)
[    12.063] (==) AMDGPU(0): Default visual is TrueColor
[    12.063] (==) AMDGPU(0): RGB weight 888
[    12.063] (II) AMDGPU(0): Using 8 bits per RGB (8 bit DAC)
[    12.063] (--) AMDGPU(0): Chipset: "Unknown AMD Radeon GPU" (ChipID = 0x1638)
[    12.063] (II) Loading sub module "fb"
[    12.063] (II) LoadModule: "fb"
[    12.063] (II) Module "fb" already built-in
[    12.063] (II) Loading sub module "dri2"
[    12.063] (II) LoadModule: "dri2"
[    12.063] (II) Module "dri2" already built-in
[    12.081] (II) Loading sub module "glamoregl"
[    12.081] (II) LoadModule: "glamoregl"
[    12.081] (II) Loading /usr/lib/xorg/modules/libglamoregl.so
[    12.083] (II) Module glamoregl: vendor="X.Org Foundation"
[    12.083] 	compiled for 1.21.1.4, module version = 1.0.1
[    12.083] 	ABI class: X.Org ANSI C Emulation, version 0.4
[    12.091] (II) AMDGPU(0): glamor X acceleration enabled on AMD RENOIR (LLVM 14.0.6, DRM 3.47, 5.19.12-arch1-1)
[    12.091] (II) AMDGPU(0): glamor detected, initialising EGL layer.
[    12.091] (==) AMDGPU(0): TearFree property default: auto
[    12.091] (==) AMDGPU(0): VariableRefresh: disabled
[    12.091] (==) AMDGPU(0): AsyncFlipSecondaries: disabled
[    12.091] (II) AMDGPU(0): KMS Pageflipping: enabled
[    12.228] (II) AMDGPU(0): Output eDP has no monitor section
[    12.230] (II) AMDGPU(0): Output HDMI-A-0 has no monitor section
[    12.250] (II) AMDGPU(0): EDID for output eDP
[    12.250] (II) AMDGPU(0): Manufacturer: NCP  Model: 4d  Serial#: 0
[    12.250] (II) AMDGPU(0): Year: 2019  Week: 51
[    12.250] (II) AMDGPU(0): EDID Version: 1.4
[    12.250] (II) AMDGPU(0): Digital Display Input
[    12.250] (II) AMDGPU(0): 8 bits per channel
[    12.250] (II) AMDGPU(0): Digital interface is DisplayPort
[    12.250] (II) AMDGPU(0): Max Image Size [cm]: horiz.: 34  vert.: 19
[    12.250] (II) AMDGPU(0): Gamma: 2.20
[    12.250] (II) AMDGPU(0): No DPMS capabilities specified
[    12.250] (II) AMDGPU(0): Supported color encodings: RGB 4:4:4 
[    12.250] (II) AMDGPU(0): First detailed timing is preferred mode
[    12.250] (II) AMDGPU(0): Preferred mode is native pixel format and refresh rate
[    12.250] (II) AMDGPU(0): Display is continuous-frequency
[    12.250] (II) AMDGPU(0): redX: 0.595 redY: 0.361   greenX: 0.346 greenY: 0.555
[    12.250] (II) AMDGPU(0): blueX: 0.157 blueY: 0.106   whiteX: 0.312 whiteY: 0.328
[    12.250] (II) AMDGPU(0): Manufacturer's mask: 0
[    12.250] (II) AMDGPU(0): Supported detailed timing:
[    12.250] (II) AMDGPU(0): clock: 354.7 MHz   Image Size:  344 x 194 mm
[    12.250] (II) AMDGPU(0): h_active: 1920  h_sync: 1968  h_sync_end 2000 h_blank_end 2180 h_border: 0
[    12.250] (II) AMDGPU(0): v_active: 1080  v_sync: 1083  v_sync_end 1088 v_blanking: 1130 v_border: 0
[    12.250] (II) AMDGPU(0): Supported detailed timing:
[    12.250] (II) AMDGPU(0): clock: 147.8 MHz   Image Size:  344 x 194 mm
[    12.250] (II) AMDGPU(0): h_active: 1920  h_sync: 1968  h_sync_end 2000 h_blank_end 2180 h_border: 0
[    12.250] (II) AMDGPU(0): v_active: 1080  v_sync: 1083  v_sync_end 1088 v_blanking: 1130 v_border: 0
[    12.250] (II) AMDGPU(0): Ranges: V min: 48 V max: 144 Hz, H min: 163 H max: 163 kHz, PixClock max 355 MHz
[    12.250] (II) AMDGPU(0):  LM156LF-2F03
[    12.250] (II) AMDGPU(0): EDID (in hex):
[    12.250] (II) AMDGPU(0): 	00ffffffffffff0038704d0000000000
[    12.250] (II) AMDGPU(0): 	331d0104a5221378036850985c588e28
[    12.250] (II) AMDGPU(0): 	1b505400000001010101010101010101
[    12.250] (II) AMDGPU(0): 	010101010101918a8004713832403020
[    12.250] (II) AMDGPU(0): 	350058c21000001abd39800471383240
[    12.250] (II) AMDGPU(0): 	3020350058c21000001a000000fd0030
[    12.250] (II) AMDGPU(0): 	90a3a323010a202020202020000000fe
[    12.250] (II) AMDGPU(0): 	004c4d3135364c462d324630330a0035
[    12.250] (II) AMDGPU(0): Printing probed modes for output eDP
[    12.250] (II) AMDGPU(0): Modeline "1920x1080"x144.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[    12.250] (II) AMDGPU(0): Modeline "1920x1080"x120.0  354.73  1920 1968 2000 2180  1080 1309 1314 1356 +hsync -vsync (162.7 kHz e)
[    12.250] (II) AMDGPU(0): Modeline "1920x1080"x96.0  354.73  1920 1968 2000 2180  1080 1648 1653 1695 +hsync -vsync (162.7 kHz e)
[    12.250] (II) AMDGPU(0): Modeline "1920x1080"x72.0  354.73  1920 1968 2000 2180  1080 2213 2218 2260 +hsync -vsync (162.7 kHz e)
[    12.250] (II) AMDGPU(0): Modeline "1920x1080"x60.0  354.73  1920 1968 2000 2180  1080 2665 2670 2712 +hsync -vsync (162.7 kHz e)
[    12.250] (II) AMDGPU(0): Modeline "1920x1080"x50.0  354.73  1920 1968 2000 2180  1080 3207 3212 3254 +hsync -vsync (162.7 kHz e)
[    12.250] (II) AMDGPU(0): Modeline "1920x1080"x48.0  354.73  1920 1968 2000 2180  1080 3343 3348 3390 +hsync -vsync (162.7 kHz e)
[    12.250] (II) AMDGPU(0): Modeline "1920x1080"x60.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[    12.250] (II) AMDGPU(0): Modeline "1680x1050"x144.0  354.73  1680 1968 2000 2180  1050 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[    12.250] (II) AMDGPU(0): Modeline "1280x1024"x144.0  354.73  1280 1968 2000 2180  1024 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[    12.250] (II) AMDGPU(0): Modeline "1440x900"x144.0  354.73  1440 1968 2000 2180  900 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[    12.250] (II) AMDGPU(0): Modeline "1280x800"x144.0  354.73  1280 1968 2000 2180  800 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[    12.251] (II) AMDGPU(0): Modeline "1280x720"x144.0  354.73  1280 1968 2000 2180  720 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[    12.251] (II) AMDGPU(0): Modeline "1024x768"x144.0  354.73  1024 1968 2000 2180  768 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[    12.251] (II) AMDGPU(0): Modeline "800x600"x144.0  354.73  800 1968 2000 2180  600 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[    12.251] (II) AMDGPU(0): Modeline "640x480"x144.0  354.73  640 1968 2000 2180  480 1083 1088 1130 +hsync -vsync (162.7 kHz e)
[    12.252] (II) AMDGPU(0): EDID for output HDMI-A-0
[    12.252] (II) AMDGPU(0): Manufacturer: SAM  Model: c4e  Serial#: 1113216587
[    12.252] (II) AMDGPU(0): Year: 2020  Week: 41
[    12.252] (II) AMDGPU(0): EDID Version: 1.3
[    12.252] (II) AMDGPU(0): Digital Display Input
[    12.252] (II) AMDGPU(0): Max Image Size [cm]: horiz.: 61  vert.: 35
[    12.252] (II) AMDGPU(0): Gamma: 2.20
[    12.252] (II) AMDGPU(0): DPMS capabilities: Off
[    12.252] (II) AMDGPU(0): Supported color encodings: RGB 4:4:4 YCrCb 4:4:4 
[    12.252] (II) AMDGPU(0): First detailed timing is preferred mode
[    12.252] (II) AMDGPU(0): redX: 0.634 redY: 0.341   greenX: 0.312 greenY: 0.636
[    12.252] (II) AMDGPU(0): blueX: 0.158 blueY: 0.062   whiteX: 0.312 whiteY: 0.329
[    12.252] (II) AMDGPU(0): Supported established timings:
[    12.252] (II) AMDGPU(0): 720x400@70Hz
[    12.252] (II) AMDGPU(0): 640x480@60Hz
[    12.252] (II) AMDGPU(0): 640x480@67Hz
[    12.252] (II) AMDGPU(0): 640x480@72Hz
[    12.252] (II) AMDGPU(0): 640x480@75Hz
[    12.252] (II) AMDGPU(0): 800x600@56Hz
[    12.252] (II) AMDGPU(0): 800x600@60Hz
[    12.252] (II) AMDGPU(0): 800x600@72Hz
[    12.252] (II) AMDGPU(0): 800x600@75Hz
[    12.252] (II) AMDGPU(0): 832x624@75Hz
[    12.252] (II) AMDGPU(0): 1024x768@60Hz
[    12.252] (II) AMDGPU(0): 1024x768@70Hz
[    12.252] (II) AMDGPU(0): 1024x768@75Hz
[    12.252] (II) AMDGPU(0): 1280x1024@75Hz
[    12.252] (II) AMDGPU(0): 1152x864@75Hz
[    12.252] (II) AMDGPU(0): Manufacturer's mask: 0
[    12.252] (II) AMDGPU(0): Supported standard timings:
[    12.252] (II) AMDGPU(0): #0: hsize: 1152  vsize 864  refresh: 75  vid: 20337
[    12.252] (II) AMDGPU(0): #1: hsize: 1280  vsize 800  refresh: 60  vid: 129
[    12.252] (II) AMDGPU(0): #2: hsize: 1280  vsize 720  refresh: 60  vid: 49281
[    12.252] (II) AMDGPU(0): #3: hsize: 1280  vsize 1024  refresh: 60  vid: 32897
[    12.252] (II) AMDGPU(0): #4: hsize: 1440  vsize 900  refresh: 60  vid: 149
[    12.252] (II) AMDGPU(0): #5: hsize: 1600  vsize 900  refresh: 60  vid: 49321
[    12.252] (II) AMDGPU(0): #6: hsize: 1680  vsize 1050  refresh: 60  vid: 179
[    12.252] (II) AMDGPU(0): Supported detailed timing:
[    12.252] (II) AMDGPU(0): clock: 297.0 MHz   Image Size:  608 x 345 mm
[    12.252] (II) AMDGPU(0): h_active: 3840  h_sync: 4016  h_sync_end 4104 h_blank_end 4400 h_border: 0
[    12.252] (II) AMDGPU(0): v_active: 2160  v_sync: 2168  v_sync_end 2178 v_blanking: 2250 v_border: 0
[    12.252] (II) AMDGPU(0): Ranges: V min: 24 V max: 75 Hz, H min: 30 H max: 90 kHz, PixClock max 305 MHz
[    12.252] (II) AMDGPU(0): Monitor name: U28E590
[    12.252] (II) AMDGPU(0): Serial No: H4ZNA00044
[    12.252] (II) AMDGPU(0): Supported detailed timing:
[    12.252] (II) AMDGPU(0): clock: 148.5 MHz   Image Size:  608 x 345 mm
[    12.252] (II) AMDGPU(0): h_active: 1920  h_sync: 2008  h_sync_end 2052 h_blank_end 2200 h_border: 0
[    12.252] (II) AMDGPU(0): v_active: 1080  v_sync: 1084  v_sync_end 1089 v_blanking: 1125 v_border: 0
[    12.252] (II) AMDGPU(0): Supported detailed timing:
[    12.252] (II) AMDGPU(0): clock: 148.5 MHz   Image Size:  608 x 345 mm
[    12.252] (II) AMDGPU(0): h_active: 1920  h_sync: 2448  h_sync_end 2492 h_blank_end 2640 h_border: 0
[    12.252] (II) AMDGPU(0): v_active: 1080  v_sync: 1084  v_sync_end 1089 v_blanking: 1125 v_border: 0
[    12.252] (II) AMDGPU(0): Supported detailed timing:
[    12.252] (II) AMDGPU(0): clock: 74.2 MHz   Image Size:  608 x 345 mm
[    12.252] (II) AMDGPU(0): h_active: 1280  h_sync: 1390  h_sync_end 1430 h_blank_end 1650 h_border: 0
[    12.252] (II) AMDGPU(0): v_active: 720  v_sync: 725  v_sync_end 730 v_blanking: 750 v_border: 0
[    12.252] (II) AMDGPU(0): Supported detailed timing:
[    12.252] (II) AMDGPU(0): clock: 241.5 MHz   Image Size:  608 x 345 mm
[    12.252] (II) AMDGPU(0): h_active: 2560  h_sync: 2608  h_sync_end 2640 h_blank_end 2720 h_border: 0
[    12.252] (II) AMDGPU(0): v_active: 1440  v_sync: 1443  v_sync_end 1448 v_blanking: 1481 v_border: 0
[    12.252] (II) AMDGPU(0): Number of EDID sections to follow: 1
[    12.252] (II) AMDGPU(0): EDID (in hex):
[    12.252] (II) AMDGPU(0): 	00ffffffffffff004c2d4e0c4b565a42
[    12.252] (II) AMDGPU(0): 	291e0103803d23782a5fb1a2574fa228
[    12.252] (II) AMDGPU(0): 	0f5054bfef80714f810081c081809500
[    12.252] (II) AMDGPU(0): 	a9c0b300010104740030f2705a80b058
[    12.252] (II) AMDGPU(0): 	8a0060592100001e000000fd00184b1e
[    12.252] (II) AMDGPU(0): 	5a1e000a202020202020000000fc0055
[    12.252] (II) AMDGPU(0): 	3238453539300a2020202020000000ff
[    12.252] (II) AMDGPU(0): 	0048345a4e4130303034340a202001d3
[    12.252] (II) AMDGPU(0): 	020324f0495f10041f13031220222309
[    12.252] (II) AMDGPU(0): 	0707830100006d030c001000803c2010
[    12.252] (II) AMDGPU(0): 	60010203023a801871382d40582c4500
[    12.252] (II) AMDGPU(0): 	60592100001e023a80d072382d40102c
[    12.252] (II) AMDGPU(0): 	458060592100001e011d007251d01e20
[    12.252] (II) AMDGPU(0): 	6e28550060592100001e565e00a0a0a0
[    12.252] (II) AMDGPU(0): 	29503020350060592100001a00000000
[    12.252] (II) AMDGPU(0): 	00000000000000000000000000000067
[    12.252] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[    12.252] (II) AMDGPU(0): Printing probed modes for output HDMI-A-0
[    12.252] (II) AMDGPU(0): Modeline "3840x2160"x30.0  297.00  3840 4016 4104 4400  2160 2168 2178 2250 +hsync +vsync (67.5 kHz eP)
[    12.252] (II) AMDGPU(0): Modeline "3840x2160"x25.0  297.00  3840 4896 4984 5280  2160 2168 2178 2250 +hsync +vsync (56.2 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "3840x2160"x24.0  297.00  3840 5116 5204 5500  2160 2168 2178 2250 +hsync +vsync (54.0 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "3840x2160"x30.0  296.70  3840 4016 4104 4400  2160 2168 2178 2250 +hsync +vsync (67.4 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "3840x2160"x24.0  296.70  3840 5116 5204 5500  2160 2168 2178 2250 +hsync +vsync (53.9 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "2560x1440"x60.0  241.50  2560 2608 2640 2720  1440 1443 1448 1481 +hsync -vsync (88.8 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1920x1200"x30.0  297.00  1920 4016 4104 4400  1200 2168 2178 2250 +hsync +vsync (67.5 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1920x1080"x60.0  148.50  1920 2008 2052 2200  1080 1084 1089 1125 +hsync +vsync (67.5 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1920x1080"x50.0  148.50  1920 2448 2492 2640  1080 1084 1089 1125 +hsync +vsync (56.2 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1920x1080"x59.9  148.35  1920 2008 2052 2200  1080 1084 1089 1125 +hsync +vsync (67.4 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1920x1080"x30.0   74.25  1920 2008 2052 2200  1080 1084 1089 1125 +hsync +vsync (33.8 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1920x1080"x24.0   74.25  1920 2558 2602 2750  1080 1084 1089 1125 +hsync +vsync (27.0 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1920x1080"x30.0   74.18  1920 2008 2052 2200  1080 1084 1089 1125 +hsync +vsync (33.7 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1920x1080"x24.0   74.18  1920 2558 2602 2750  1080 1084 1089 1125 +hsync +vsync (27.0 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1600x1200"x30.0  297.00  1600 4016 4104 4400  1200 2168 2178 2250 +hsync +vsync (67.5 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1680x1050"x59.9  119.00  1680 1728 1760 1840  1050 1053 1059 1080 +hsync -vsync (64.7 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1600x900"x60.0  108.00  1600 1624 1704 1800  900 901 904 1000 +hsync +vsync (60.0 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1280x1024"x75.0  135.00  1280 1296 1440 1688  1024 1025 1028 1066 +hsync +vsync (80.0 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1280x1024"x60.0  108.00  1280 1328 1440 1688  1024 1025 1028 1066 +hsync +vsync (64.0 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1440x900"x59.9   88.75  1440 1488 1520 1600  900 903 909 926 +hsync -vsync (55.5 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1280x800"x59.9   71.00  1280 1328 1360 1440  800 803 809 823 +hsync -vsync (49.3 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1152x864"x75.0  108.00  1152 1216 1344 1600  864 865 868 900 +hsync +vsync (67.5 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1280x720"x60.0   74.25  1280 1390 1430 1650  720 725 730 750 +hsync +vsync (45.0 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1280x720"x50.0   74.25  1280 1720 1760 1980  720 725 730 750 +hsync +vsync (37.5 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1280x720"x59.9   74.18  1280 1390 1430 1650  720 725 730 750 +hsync +vsync (45.0 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1024x768"x75.0   78.75  1024 1040 1136 1312  768 769 772 800 +hsync +vsync (60.0 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1024x768"x70.1   75.00  1024 1048 1184 1328  768 771 777 806 -hsync -vsync (56.5 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "1024x768"x60.0   65.00  1024 1048 1184 1344  768 771 777 806 -hsync -vsync (48.4 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "832x624"x74.6   57.28  832 864 928 1152  624 625 628 667 -hsync -vsync (49.7 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "800x600"x72.2   50.00  800 856 976 1040  600 637 643 666 +hsync +vsync (48.1 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "800x600"x75.0   49.50  800 816 896 1056  600 601 604 625 +hsync +vsync (46.9 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "800x600"x60.3   40.00  800 840 968 1056  600 601 605 628 +hsync +vsync (37.9 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "800x600"x56.2   36.00  800 824 896 1024  600 601 603 625 +hsync +vsync (35.2 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "720x576"x50.0   27.00  720 732 796 864  576 581 586 625 -hsync -vsync (31.2 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "720x480"x60.0   27.03  720 736 798 858  480 489 495 525 -hsync -vsync (31.5 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "720x480"x59.9   27.00  720 736 798 858  480 489 495 525 -hsync -vsync (31.5 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "640x480"x75.0   31.50  640 656 720 840  480 481 484 500 -hsync -vsync (37.5 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "640x480"x72.8   31.50  640 664 704 832  480 489 492 520 -hsync -vsync (37.9 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "640x480"x66.7   30.24  640 704 768 864  480 483 486 525 -hsync -vsync (35.0 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "640x480"x60.0   25.20  640 656 752 800  480 490 492 525 -hsync -vsync (31.5 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "640x480"x59.9   25.18  640 656 752 800  480 490 492 525 -hsync -vsync (31.5 kHz e)
[    12.252] (II) AMDGPU(0): Modeline "720x400"x70.1   28.32  720 738 846 900  400 412 414 449 -hsync +vsync (31.5 kHz e)
[    12.252] (II) AMDGPU(0): Output eDP connected
[    12.252] (II) AMDGPU(0): Output HDMI-A-0 connected
[    12.252] (II) AMDGPU(0): Using spanning desktop for initial modes
[    12.252] (II) AMDGPU(0): Output eDP using initial mode 1920x1080 +0+0
[    12.252] (II) AMDGPU(0): Output HDMI-A-0 using initial mode 3840x2160 +1920+0
[    12.252] (II) AMDGPU(0): mem size init: gart size :7c642e800 vram size: s:1e715000 visible:1e715000
[    12.252] (==) AMDGPU(0): DPI set to (96, 96)
[    12.252] (==) AMDGPU(0): Using gamma correction (1.0, 1.0, 1.0)
[    12.252] (II) Loading sub module "ramdac"
[    12.252] (II) LoadModule: "ramdac"
[    12.253] (II) Module "ramdac" already built-in
[    12.253] (==) NVIDIA(G0): Depth 24, (==) framebuffer bpp 32
[    12.253] (==) NVIDIA(G0): RGB weight 888
[    12.253] (==) NVIDIA(G0): Default visual is TrueColor
[    12.253] (==) NVIDIA(G0): Using gamma correction (1.0, 1.0, 1.0)
[    12.253] (II) Applying OutputClass "nvidia" options to /dev/dri/card1
[    12.253] (**) NVIDIA(G0): Option "AllowEmptyInitialConfiguration"
[    12.253] (**) NVIDIA(G0): Enabling 2D acceleration
[    12.253] (II) Loading sub module "glxserver_nvidia"
[    12.253] (II) LoadModule: "glxserver_nvidia"
[    12.253] (II) Loading /usr/lib/nvidia/xorg/libglxserver_nvidia.so
[    12.257] (II) Module glxserver_nvidia: vendor="NVIDIA Corporation"
[    12.257] 	compiled for 1.6.99.901, module version = 1.0.0
[    12.257] 	Module class: X.Org Server Extension
[    12.257] (II) NVIDIA GLX Module  515.76  Mon Sep 12 19:14:20 UTC 2022
[    12.257] (II) NVIDIA: The X server supports PRIME Render Offload.
[    12.257] (--) NVIDIA(0): Valid display device(s) on GPU-0 at PCI:1:0:0
[    12.257] (--) NVIDIA(0):     DFP-0
[    12.257] (--) NVIDIA(0):     DFP-1
[    12.258] (II) NVIDIA(G0): NVIDIA GPU NVIDIA GeForce RTX 3060 Laptop GPU (GA106-A) at
[    12.258] (II) NVIDIA(G0):     PCI:1:0:0 (GPU-0)
[    12.258] (--) NVIDIA(G0): Memory: 6291456 kBytes
[    12.258] (--) NVIDIA(G0): VideoBIOS: 94.06.17.00.5f
[    12.258] (II) NVIDIA(G0): Detected PCI Express Link width: 16X
[    12.258] (--) NVIDIA(GPU-0): DFP-0: disconnected
[    12.258] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[    12.258] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[    12.258] (--) NVIDIA(GPU-0): 
[    12.258] (--) NVIDIA(GPU-0): DFP-1: disconnected
[    12.258] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[    12.258] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[    12.258] (--) NVIDIA(GPU-0): 
[    12.259] (II) NVIDIA(G0): Validated MetaModes:
[    12.259] (II) NVIDIA(G0):     "NULL"
[    12.259] (II) NVIDIA(G0): Virtual screen size determined to be 640 x 480
[    12.259] (WW) NVIDIA(G0): Unable to get display device for DPI computation.
[    12.259] (==) NVIDIA(G0): DPI set to (75, 75); computed from built-in default
[    12.259] (II) UnloadModule: "modesetting"
[    12.259] (II) Unloading modesetting
[    12.259] (II) UnloadModule: "fbdev"
[    12.259] (II) Unloading fbdev
[    12.259] (II) UnloadSubModule: "fbdevhw"
[    12.259] (II) Unloading fbdevhw
[    12.259] (II) UnloadModule: "vesa"
[    12.259] (II) Unloading vesa
[    12.259] (II) AMDGPU(0): [DRI2] Setup complete
[    12.259] (II) AMDGPU(0): [DRI2]   DRI driver: radeonsi
[    12.259] (II) AMDGPU(0): [DRI2]   VDPAU driver: radeonsi
[    12.273] (II) AMDGPU(0): Front buffer pitch: 23040 bytes
[    12.273] (II) AMDGPU(0): SYNC extension fences enabled
[    12.273] (II) AMDGPU(0): Present extension enabled
[    12.273] (==) AMDGPU(0): DRI3 enabled
[    12.273] (==) AMDGPU(0): Backing store enabled
[    12.273] (II) AMDGPU(0): Direct rendering enabled
[    12.289] (II) AMDGPU(0): Use GLAMOR acceleration.
[    12.289] (II) AMDGPU(0): Acceleration enabled
[    12.289] (==) AMDGPU(0): DPMS enabled
[    12.289] (==) AMDGPU(0): Silken mouse enabled
[    12.289] (II) AMDGPU(0): Set up textured video (glamor)
[    12.290] (II) NVIDIA: Reserving 24576.00 MB of virtual memory for indirect memory
[    12.290] (II) NVIDIA:     access.
[    12.298] (II) NVIDIA(G0): ACPI: failed to connect to the ACPI event daemon; the daemon
[    12.298] (II) NVIDIA(G0):     may not be running or the "AcpidSocketPath" X
[    12.298] (II) NVIDIA(G0):     configuration option may not be set correctly.  When the
[    12.298] (II) NVIDIA(G0):     ACPI event daemon is available, the NVIDIA X driver will
[    12.298] (II) NVIDIA(G0):     try to use it to receive ACPI event notifications.  For
[    12.298] (II) NVIDIA(G0):     details, please see the "ConnectToAcpid" and
[    12.298] (II) NVIDIA(G0):     "AcpidSocketPath" X configuration options in Appendix B: X
[    12.298] (II) NVIDIA(G0):     Config Options in the README.
[    12.311] (II) NVIDIA(G0): Setting mode "NULL"
[    12.319] (==) NVIDIA(G0): Disabling shared memory pixmaps
[    12.319] (==) NVIDIA(G0): Backing store enabled
[    12.319] (==) NVIDIA(G0): Silken mouse enabled
[    12.320] (==) NVIDIA(G0): DPMS enabled
[    12.320] (II) Loading sub module "dri2"
[    12.320] (II) LoadModule: "dri2"
[    12.320] (II) Module "dri2" already built-in
[    12.320] (II) NVIDIA(G0): [DRI2] Setup complete
[    12.320] (II) NVIDIA(G0): [DRI2]   VDPAU driver: nvidia
[    12.320] (II) Initializing extension Generic Event Extension
[    12.320] (II) Initializing extension SHAPE
[    12.320] (II) Initializing extension MIT-SHM
[    12.320] (II) Initializing extension XInputExtension
[    12.320] (II) Initializing extension XTEST
[    12.320] (II) Initializing extension BIG-REQUESTS
[    12.320] (II) Initializing extension SYNC
[    12.320] (II) Initializing extension XKEYBOARD
[    12.320] (II) Initializing extension XC-MISC
[    12.320] (II) Initializing extension SECURITY
[    12.320] (II) Initializing extension XFIXES
[    12.320] (II) Initializing extension RENDER
[    12.320] (II) Initializing extension RANDR
[    12.320] (II) Initializing extension COMPOSITE
[    12.321] (II) Initializing extension DAMAGE
[    12.321] (II) Initializing extension MIT-SCREEN-SAVER
[    12.321] (II) Initializing extension DOUBLE-BUFFER
[    12.321] (II) Initializing extension RECORD
[    12.321] (II) Initializing extension DPMS
[    12.321] (II) Initializing extension Present
[    12.321] (II) Initializing extension DRI3
[    12.321] (II) Initializing extension X-Resource
[    12.321] (II) Initializing extension XVideo
[    12.321] (II) Initializing extension XVideo-MotionCompensation
[    12.321] (II) Initializing extension GLX
[    12.321] (II) Initializing extension GLX
[    12.321] (II) Indirect GLX disabled.
[    12.324] (II) AIGLX: Loaded and initialized radeonsi
[    12.324] (II) GLX: Initialized DRI2 GL provider for screen 0
[    12.324] (II) Initializing extension XFree86-VidModeExtension
[    12.324] (II) Initializing extension XFree86-DGA
[    12.324] (II) Initializing extension XFree86-DRI
[    12.324] (II) Initializing extension DRI2
[    12.324] (II) Initializing extension NV-GLX
[    12.324] (II) Initializing extension NV-CONTROL
[    12.325] (II) AMDGPU(0): Setting screen physical size to 1524 x 571
[    12.957] (II) config/udev: Adding input device Asus Wireless Radio Control (/dev/input/event4)
[    12.957] (**) Asus Wireless Radio Control: Applying InputClass "libinput keyboard catchall"
[    12.957] (II) LoadModule: "libinput"
[    12.957] (II) Loading /usr/lib/xorg/modules/input/libinput_drv.so
[    12.958] (II) Module libinput: vendor="X.Org Foundation"
[    12.958] 	compiled for 1.21.1.3, module version = 1.2.1
[    12.958] 	Module class: X.Org XInput Driver
[    12.958] 	ABI class: X.Org XInput driver, version 24.4
[    12.958] (II) Using input driver 'libinput' for 'Asus Wireless Radio Control'
[    12.959] (II) systemd-logind: got fd for /dev/input/event4 13:68 fd 49 paused 0
[    12.959] (**) Asus Wireless Radio Control: always reports core events
[    12.959] (**) Option "Device" "/dev/input/event4"
[    12.960] (II) event4  - Asus Wireless Radio Control: is tagged by udev as: Keyboard
[    12.960] (II) event4  - Asus Wireless Radio Control: device is a keyboard
[    12.960] (II) event4  - Asus Wireless Radio Control: device removed
[    12.960] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/ATK4002:00/input/input4/event4"
[    12.960] (II) XINPUT: Adding extended input device "Asus Wireless Radio Control" (type: KEYBOARD, id 6)
[    12.961] (II) event4  - Asus Wireless Radio Control: is tagged by udev as: Keyboard
[    12.961] (II) event4  - Asus Wireless Radio Control: device is a keyboard
[    12.961] (II) config/udev: Adding input device Video Bus (/dev/input/event5)
[    12.961] (**) Video Bus: Applying InputClass "libinput keyboard catchall"
[    12.961] (II) Using input driver 'libinput' for 'Video Bus'
[    12.961] (II) systemd-logind: got fd for /dev/input/event5 13:69 fd 52 paused 0
[    12.961] (**) Video Bus: always reports core events
[    12.962] (**) Option "Device" "/dev/input/event5"
[    12.962] (II) event5  - Video Bus: is tagged by udev as: Keyboard
[    12.962] (II) event5  - Video Bus: device is a keyboard
[    12.962] (II) event5  - Video Bus: device removed
[    12.962] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/PNP0A08:00/device:01/LNXVIDEO:00/input/input5/event5"
[    12.962] (II) XINPUT: Adding extended input device "Video Bus" (type: KEYBOARD, id 7)
[    12.963] (II) event5  - Video Bus: is tagged by udev as: Keyboard
[    12.963] (II) event5  - Video Bus: device is a keyboard
[    12.963] (II) config/udev: Adding input device Video Bus (/dev/input/event6)
[    12.963] (**) Video Bus: Applying InputClass "libinput keyboard catchall"
[    12.963] (II) Using input driver 'libinput' for 'Video Bus'
[    12.963] (II) systemd-logind: got fd for /dev/input/event6 13:70 fd 53 paused 0
[    12.963] (**) Video Bus: always reports core events
[    12.963] (**) Option "Device" "/dev/input/event6"
[    12.964] (II) event6  - Video Bus: is tagged by udev as: Keyboard
[    12.964] (II) event6  - Video Bus: device is a keyboard
[    12.964] (II) event6  - Video Bus: device removed
[    12.964] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/PNP0A08:00/device:0f/LNXVIDEO:01/input/input6/event6"
[    12.964] (II) XINPUT: Adding extended input device "Video Bus" (type: KEYBOARD, id 8)
[    12.965] (II) event6  - Video Bus: is tagged by udev as: Keyboard
[    12.965] (II) event6  - Video Bus: device is a keyboard
[    12.965] (II) config/udev: Adding input device Power Button (/dev/input/event0)
[    12.965] (**) Power Button: Applying InputClass "libinput keyboard catchall"
[    12.965] (II) Using input driver 'libinput' for 'Power Button'
[    12.965] (II) systemd-logind: got fd for /dev/input/event0 13:64 fd 54 paused 0
[    12.965] (**) Power Button: always reports core events
[    12.965] (**) Option "Device" "/dev/input/event0"
[    12.966] (II) event0  - Power Button: is tagged by udev as: Keyboard
[    12.966] (II) event0  - Power Button: device is a keyboard
[    12.966] (II) event0  - Power Button: device removed
[    12.966] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/PNP0C0C:00/input/input0/event0"
[    12.966] (II) XINPUT: Adding extended input device "Power Button" (type: KEYBOARD, id 9)
[    12.966] (II) event0  - Power Button: is tagged by udev as: Keyboard
[    12.966] (II) event0  - Power Button: device is a keyboard
[    12.966] (II) config/udev: Adding input device Lid Switch (/dev/input/event2)
[    12.966] (II) No input driver specified, ignoring this device.
[    12.966] (II) This device may have been added with another device file.
[    12.967] (II) config/udev: Adding input device Sleep Button (/dev/input/event1)
[    12.967] (**) Sleep Button: Applying InputClass "libinput keyboard catchall"
[    12.967] (II) Using input driver 'libinput' for 'Sleep Button'
[    12.967] (II) systemd-logind: got fd for /dev/input/event1 13:65 fd 55 paused 0
[    12.967] (**) Sleep Button: always reports core events
[    12.967] (**) Option "Device" "/dev/input/event1"
[    12.967] (II) event1  - Sleep Button: is tagged by udev as: Keyboard
[    12.967] (II) event1  - Sleep Button: device is a keyboard
[    12.967] (II) event1  - Sleep Button: device removed
[    12.967] (**) Option "config_info" "udev:/sys/devices/LNXSYSTM:00/LNXSYBUS:00/PNP0C0E:00/input/input1/event1"
[    12.967] (II) XINPUT: Adding extended input device "Sleep Button" (type: KEYBOARD, id 10)
[    12.968] (II) event1  - Sleep Button: is tagged by udev as: Keyboard
[    12.968] (II) event1  - Sleep Button: device is a keyboard
[    12.968] (II) config/udev: Adding input device HDA NVidia HDMI/DP,pcm=3 (/dev/input/event15)
[    12.968] (II) No input driver specified, ignoring this device.
[    12.968] (II) This device may have been added with another device file.
[    12.968] (II) config/udev: Adding input device HDA NVidia HDMI/DP,pcm=7 (/dev/input/event16)
[    12.968] (II) No input driver specified, ignoring this device.
[    12.968] (II) This device may have been added with another device file.
[    12.969] (II) config/udev: Adding input device HDA NVidia HDMI/DP,pcm=8 (/dev/input/event17)
[    12.969] (II) No input driver specified, ignoring this device.
[    12.969] (II) This device may have been added with another device file.
[    12.969] (II) config/udev: Adding input device HDA NVidia HDMI/DP,pcm=9 (/dev/input/event10)
[    12.969] (II) No input driver specified, ignoring this device.
[    12.969] (II) This device may have been added with another device file.
[    12.969] (II) config/udev: Adding input device HD-Audio Generic HDMI/DP,pcm=3 (/dev/input/event8)
[    12.969] (II) No input driver specified, ignoring this device.
[    12.969] (II) This device may have been added with another device file.
[    12.969] (II) config/udev: Adding input device Logitech Wireless Keyboard PID:4023 (/dev/input/event18)
[    12.969] (**) Logitech Wireless Keyboard PID:4023: Applying InputClass "libinput keyboard catchall"
[    12.969] (II) Using input driver 'libinput' for 'Logitech Wireless Keyboard PID:4023'
[    12.970] (II) systemd-logind: got fd for /dev/input/event18 13:82 fd 56 paused 0
[    12.970] (**) Logitech Wireless Keyboard PID:4023: always reports core events
[    12.970] (**) Option "Device" "/dev/input/event18"
[    12.970] (II) event18 - Logitech Wireless Keyboard PID:4023: is tagged by udev as: Keyboard
[    12.971] (II) event18 - Logitech Wireless Keyboard PID:4023: device is a keyboard
[    12.971] (II) event18 - Logitech Wireless Keyboard PID:4023: device removed
[    12.971] (II) libinput: Logitech Wireless Keyboard PID:4023: needs a virtual subdevice
[    12.971] (**) Option "config_info" "udev:/sys/devices/pci0000:00/0000:00:08.1/0000:06:00.3/usb1/1-2/1-2:1.1/0003:046D:C534.0002/0003:046D:4023.0004/input/input35/event18"
[    12.971] (II) XINPUT: Adding extended input device "Logitech Wireless Keyboard PID:4023" (type: MOUSE, id 11)
[    12.971] (**) Option "AccelerationScheme" "none"
[    12.971] (**) Logitech Wireless Keyboard PID:4023: (accel) selected scheme none/0
[    12.971] (**) Logitech Wireless Keyboard PID:4023: (accel) acceleration factor: 2.000
[    12.971] (**) Logitech Wireless Keyboard PID:4023: (accel) acceleration threshold: 4
[    12.971] (II) event18 - Logitech Wireless Keyboard PID:4023: is tagged by udev as: Keyboard
[    12.972] (II) event18 - Logitech Wireless Keyboard PID:4023: device is a keyboard
[    12.972] (II) config/udev: Adding input device Logitech Wireless Mouse (/dev/input/event19)
[    12.972] (**) Logitech Wireless Mouse: Applying InputClass "libinput pointer catchall"
[    12.972] (II) Using input driver 'libinput' for 'Logitech Wireless Mouse'
[    12.972] (II) systemd-logind: got fd for /dev/input/event19 13:83 fd 57 paused 0
[    12.972] (**) Logitech Wireless Mouse: always reports core events
[    12.972] (**) Option "Device" "/dev/input/event19"
[    12.973] (II) event19 - Logitech Wireless Mouse: is tagged by udev as: Mouse
[    12.973] (II) event19 - Logitech Wireless Mouse: device is a pointer
[    12.973] (II) event19 - Logitech Wireless Mouse: device removed
[    12.973] (**) Option "config_info" "udev:/sys/devices/pci0000:00/0000:00:08.1/0000:06:00.3/usb1/1-2/1-2:1.1/0003:046D:C534.0002/0003:046D:4058.0005/input/input36/event19"
[    12.973] (II) XINPUT: Adding extended input device "Logitech Wireless Mouse" (type: MOUSE, id 12)
[    12.973] (**) Option "AccelerationScheme" "none"
[    12.973] (**) Logitech Wireless Mouse: (accel) selected scheme none/0
[    12.973] (**) Logitech Wireless Mouse: (accel) acceleration factor: 2.000
[    12.973] (**) Logitech Wireless Mouse: (accel) acceleration threshold: 4
[    12.974] (II) event19 - Logitech Wireless Mouse: is tagged by udev as: Mouse
[    12.974] (II) event19 - Logitech Wireless Mouse: device is a pointer
[    12.975] (II) config/udev: Adding input device Logitech Wireless Mouse (/dev/input/mouse2)
[    12.975] (II) No input driver specified, ignoring this device.
[    12.975] (II) This device may have been added with another device file.
[    12.975] (II) config/udev: Adding input device USB2.0 HD UVC WebCam: USB2.0 HD (/dev/input/event11)
[    12.975] (**) USB2.0 HD UVC WebCam: USB2.0 HD: Applying InputClass "libinput keyboard catchall"
[    12.975] (II) Using input driver 'libinput' for 'USB2.0 HD UVC WebCam: USB2.0 HD'
[    12.975] (II) systemd-logind: got fd for /dev/input/event11 13:75 fd 58 paused 0
[    12.975] (**) USB2.0 HD UVC WebCam: USB2.0 HD: always reports core events
[    12.975] (**) Option "Device" "/dev/input/event11"
[    12.976] (II) event11 - USB2.0 HD UVC WebCam: USB2.0 HD: is tagged by udev as: Keyboard
[    12.976] (II) event11 - USB2.0 HD UVC WebCam: USB2.0 HD: device is a keyboard
[    12.976] (II) event11 - USB2.0 HD UVC WebCam: USB2.0 HD: device removed
[    12.976] (**) Option "config_info" "udev:/sys/devices/pci0000:00/0000:00:08.1/0000:06:00.3/usb1/1-4/1-4:1.0/input/input23/event11"
[    12.976] (II) XINPUT: Adding extended input device "USB2.0 HD UVC WebCam: USB2.0 HD" (type: KEYBOARD, id 13)
[    12.977] (II) event11 - USB2.0 HD UVC WebCam: USB2.0 HD: is tagged by udev as: Keyboard
[    12.977] (II) event11 - USB2.0 HD UVC WebCam: USB2.0 HD: device is a keyboard
[    12.977] (II) config/udev: Adding input device HD-Audio Generic Headphone (/dev/input/event9)
[    12.977] (II) No input driver specified, ignoring this device.
[    12.977] (II) This device may have been added with another device file.
[    12.977] (II) config/udev: Adding input device ELAN1203:00 04F3:307A Mouse (/dev/input/event12)
[    12.977] (**) ELAN1203:00 04F3:307A Mouse: Applying InputClass "libinput pointer catchall"
[    12.977] (II) Using input driver 'libinput' for 'ELAN1203:00 04F3:307A Mouse'
[    12.977] (II) systemd-logind: got fd for /dev/input/event12 13:76 fd 59 paused 0
[    12.977] (**) ELAN1203:00 04F3:307A Mouse: always reports core events
[    12.977] (**) Option "Device" "/dev/input/event12"
[    12.978] (II) event12 - ELAN1203:00 04F3:307A Mouse: is tagged by udev as: Mouse Pointingstick
[    12.978] (II) event12 - ELAN1203:00 04F3:307A Mouse: device is a pointer
[    12.979] (II) event12 - ELAN1203:00 04F3:307A Mouse: device removed
[    12.979] (**) Option "config_info" "udev:/sys/devices/platform/AMDI0010:03/i2c-0/i2c-ELAN1203:00/0018:04F3:307A.0003/input/input24/event12"
[    12.979] (II) XINPUT: Adding extended input device "ELAN1203:00 04F3:307A Mouse" (type: MOUSE, id 14)
[    12.979] (**) Option "AccelerationScheme" "none"
[    12.979] (**) ELAN1203:00 04F3:307A Mouse: (accel) selected scheme none/0
[    12.979] (**) ELAN1203:00 04F3:307A Mouse: (accel) acceleration factor: 2.000
[    12.979] (**) ELAN1203:00 04F3:307A Mouse: (accel) acceleration threshold: 4
[    12.979] (II) event12 - ELAN1203:00 04F3:307A Mouse: is tagged by udev as: Mouse Pointingstick
[    12.979] (II) event12 - ELAN1203:00 04F3:307A Mouse: device is a pointer
[    12.980] (II) config/udev: Adding input device ELAN1203:00 04F3:307A Mouse (/dev/input/mouse0)
[    12.980] (II) No input driver specified, ignoring this device.
[    12.980] (II) This device may have been added with another device file.
[    12.980] (II) config/udev: Adding input device ELAN1203:00 04F3:307A Touchpad (/dev/input/event13)
[    12.980] (**) ELAN1203:00 04F3:307A Touchpad: Applying InputClass "libinput touchpad catchall"
[    12.980] (II) Using input driver 'libinput' for 'ELAN1203:00 04F3:307A Touchpad'
[    12.981] (II) systemd-logind: got fd for /dev/input/event13 13:77 fd 60 paused 0
[    12.981] (**) ELAN1203:00 04F3:307A Touchpad: always reports core events
[    12.981] (**) Option "Device" "/dev/input/event13"
[    12.981] (II) event13 - ELAN1203:00 04F3:307A Touchpad: is tagged by udev as: Touchpad
[    12.982] (II) event13 - ELAN1203:00 04F3:307A Touchpad: device is a touchpad
[    12.982] (II) event13 - ELAN1203:00 04F3:307A Touchpad: device removed
[    12.982] (**) Option "config_info" "udev:/sys/devices/platform/AMDI0010:03/i2c-0/i2c-ELAN1203:00/0018:04F3:307A.0003/input/input25/event13"
[    12.982] (II) XINPUT: Adding extended input device "ELAN1203:00 04F3:307A Touchpad" (type: TOUCHPAD, id 15)
[    12.982] (**) Option "AccelerationScheme" "none"
[    12.982] (**) ELAN1203:00 04F3:307A Touchpad: (accel) selected scheme none/0
[    12.983] (**) ELAN1203:00 04F3:307A Touchpad: (accel) acceleration factor: 2.000
[    12.983] (**) ELAN1203:00 04F3:307A Touchpad: (accel) acceleration threshold: 4
[    12.983] (II) event13 - ELAN1203:00 04F3:307A Touchpad: is tagged by udev as: Touchpad
[    12.984] (II) event13 - ELAN1203:00 04F3:307A Touchpad: device is a touchpad
[    12.984] (II) config/udev: Adding input device ELAN1203:00 04F3:307A Touchpad (/dev/input/mouse1)
[    12.984] (II) No input driver specified, ignoring this device.
[    12.984] (II) This device may have been added with another device file.
[    12.984] (II) config/udev: Adding input device Asus WMI hotkeys (/dev/input/event14)
[    12.984] (**) Asus WMI hotkeys: Applying InputClass "libinput keyboard catchall"
[    12.984] (II) Using input driver 'libinput' for 'Asus WMI hotkeys'
[    12.984] (II) systemd-logind: got fd for /dev/input/event14 13:78 fd 61 paused 0
[    12.984] (**) Asus WMI hotkeys: always reports core events
[    12.984] (**) Option "Device" "/dev/input/event14"
[    12.985] (II) event14 - Asus WMI hotkeys: is tagged by udev as: Keyboard
[    12.985] (II) event14 - Asus WMI hotkeys: device is a keyboard
[    12.985] (II) event14 - Asus WMI hotkeys: device removed
[    12.985] (**) Option "config_info" "udev:/sys/devices/platform/asus-nb-wmi/input/input16/event14"
[    12.985] (II) XINPUT: Adding extended input device "Asus WMI hotkeys" (type: KEYBOARD, id 16)
[    12.985] (II) event14 - Asus WMI hotkeys: is tagged by udev as: Keyboard
[    12.985] (II) event14 - Asus WMI hotkeys: device is a keyboard
[    12.986] (II) config/udev: Adding input device AT Translated Set 2 keyboard (/dev/input/event3)
[    12.986] (**) AT Translated Set 2 keyboard: Applying InputClass "libinput keyboard catchall"
[    12.986] (II) Using input driver 'libinput' for 'AT Translated Set 2 keyboard'
[    12.986] (II) systemd-logind: got fd for /dev/input/event3 13:67 fd 62 paused 0
[    12.986] (**) AT Translated Set 2 keyboard: always reports core events
[    12.986] (**) Option "Device" "/dev/input/event3"
[    12.986] (II) event3  - AT Translated Set 2 keyboard: is tagged by udev as: Keyboard
[    12.987] (II) event3  - AT Translated Set 2 keyboard: device is a keyboard
[    12.987] (II) event3  - AT Translated Set 2 keyboard: device removed
[    12.987] (**) Option "config_info" "udev:/sys/devices/platform/i8042/serio0/input/input3/event3"
[    12.987] (II) XINPUT: Adding extended input device "AT Translated Set 2 keyboard" (type: KEYBOARD, id 17)
[    12.988] (II) event3  - AT Translated Set 2 keyboard: is tagged by udev as: Keyboard
[    12.988] (II) event3  - AT Translated Set 2 keyboard: device is a keyboard
[    12.988] (II) config/udev: Adding input device PC Speaker (/dev/input/event7)
[    12.988] (II) No input driver specified, ignoring this device.
[    12.988] (II) This device may have been added with another device file.
[    12.996] (**) Logitech Wireless Keyboard PID:4023: Applying InputClass "libinput keyboard catchall"
[    12.996] (II) Using input driver 'libinput' for 'Logitech Wireless Keyboard PID:4023'
[    12.996] (II) systemd-logind: returning pre-existing fd for /dev/input/event18 13:82
[    12.996] (**) Logitech Wireless Keyboard PID:4023: always reports core events
[    12.996] (**) Option "Device" "/dev/input/event18"
[    12.996] (II) libinput: Logitech Wireless Keyboard PID:4023: is a virtual subdevice
[    12.996] (**) Option "config_info" "udev:/sys/devices/pci0000:00/0000:00:08.1/0000:06:00.3/usb1/1-2/1-2:1.1/0003:046D:C534.0002/0003:046D:4023.0004/input/input35/event18"
[    12.996] (II) XINPUT: Adding extended input device "Logitech Wireless Keyboard PID:4023" (type: KEYBOARD, id 18)
[    13.231] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[    13.231] (II) AMDGPU(0): Using EDID range info for horizontal sync
[    13.231] (II) AMDGPU(0): Using EDID range info for vertical refresh
[    13.231] (II) AMDGPU(0): Printing DDC gathered Modelines:
[    13.231] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[    13.231] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[    13.233] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[    13.235] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[    13.235] (II) AMDGPU(0): Using hsync ranges from config file
[    13.235] (II) AMDGPU(0): Using vrefresh ranges from config file
[    13.235] (II) AMDGPU(0): Printing DDC gathered Modelines:
[    13.235] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[    13.235] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[    13.236] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[    13.236] (--) NVIDIA(GPU-0): DFP-0: disconnected
[    13.236] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[    13.236] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[    13.236] (--) NVIDIA(GPU-0): 
[    13.237] (--) NVIDIA(GPU-0): DFP-1: disconnected
[    13.237] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[    13.237] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[    13.237] (--) NVIDIA(GPU-0): 
[    14.015] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[    14.015] (II) AMDGPU(0): Using hsync ranges from config file
[    14.015] (II) AMDGPU(0): Using vrefresh ranges from config file
[    14.015] (II) AMDGPU(0): Printing DDC gathered Modelines:
[    14.015] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[    14.015] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[    14.016] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[    14.019] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[    14.019] (II) AMDGPU(0): Using hsync ranges from config file
[    14.019] (II) AMDGPU(0): Using vrefresh ranges from config file
[    14.019] (II) AMDGPU(0): Printing DDC gathered Modelines:
[    14.019] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[    14.019] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[    14.020] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[    14.020] (--) NVIDIA(GPU-0): DFP-0: disconnected
[    14.020] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[    14.020] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[    14.020] (--) NVIDIA(GPU-0): 
[    14.020] (--) NVIDIA(GPU-0): DFP-1: disconnected
[    14.020] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[    14.020] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[    14.020] (--) NVIDIA(GPU-0): 
[    14.654] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[    14.654] (II) AMDGPU(0): Using hsync ranges from config file
[    14.654] (II) AMDGPU(0): Using vrefresh ranges from config file
[    14.654] (II) AMDGPU(0): Printing DDC gathered Modelines:
[    14.654] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[    14.654] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[    14.655] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[    14.657] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[    14.657] (II) AMDGPU(0): Using hsync ranges from config file
[    14.657] (II) AMDGPU(0): Using vrefresh ranges from config file
[    14.657] (II) AMDGPU(0): Printing DDC gathered Modelines:
[    14.657] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[    14.657] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[    14.659] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[    14.659] (--) NVIDIA(GPU-0): DFP-0: disconnected
[    14.659] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[    14.659] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[    14.659] (--) NVIDIA(GPU-0): 
[    14.659] (--) NVIDIA(GPU-0): DFP-1: disconnected
[    14.659] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[    14.659] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[    14.659] (--) NVIDIA(GPU-0): 
[    15.333] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[    15.333] (II) AMDGPU(0): Using hsync ranges from config file
[    15.333] (II) AMDGPU(0): Using vrefresh ranges from config file
[    15.333] (II) AMDGPU(0): Printing DDC gathered Modelines:
[    15.333] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[    15.333] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[    15.334] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[    15.336] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[    15.336] (II) AMDGPU(0): Using hsync ranges from config file
[    15.336] (II) AMDGPU(0): Using vrefresh ranges from config file
[    15.336] (II) AMDGPU(0): Printing DDC gathered Modelines:
[    15.336] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[    15.337] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[    15.338] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[    15.338] (--) NVIDIA(GPU-0): DFP-0: disconnected
[    15.338] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[    15.338] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[    15.338] (--) NVIDIA(GPU-0): 
[    15.338] (--) NVIDIA(GPU-0): DFP-1: disconnected
[    15.338] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[    15.338] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[    15.338] (--) NVIDIA(GPU-0): 
[  2457.416] (EE) event18 - Logitech Wireless Keyboard PID:4023: client bug: event processing lagging behind by 31ms, your system is too slow
[  5432.885] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5432.885] (II) AMDGPU(0): Using hsync ranges from config file
[  5432.885] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5432.885] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5432.885] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5432.885] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5432.891] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5432.891] (II) AMDGPU(0): Using hsync ranges from config file
[  5432.891] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5432.891] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5432.891] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5432.891] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5432.893] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5432.893] (II) AMDGPU(0): Using hsync ranges from config file
[  5432.893] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5432.893] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5432.893] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5432.893] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5432.893] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  5432.893] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  5432.893] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  5432.893] (--) NVIDIA(GPU-0): 
[  5432.894] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  5432.894] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  5432.894] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  5432.894] (--) NVIDIA(GPU-0): 
[  5433.031] (EE) AMDGPU(0): drmmode_do_crtc_dpms cannot get last vblank counter
[  5433.032] (II) AMDGPU(0): Allocate new frame buffer 1920x1080
[  5433.032] (II) AMDGPU(0):  => pitch 7680 bytes
[  5433.074] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5433.074] (II) AMDGPU(0): Using hsync ranges from config file
[  5433.074] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5433.074] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5433.074] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5433.074] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5433.076] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5433.076] (II) AMDGPU(0): Using hsync ranges from config file
[  5433.076] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5433.076] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5433.076] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5433.076] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5433.076] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  5433.076] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  5433.076] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  5433.076] (--) NVIDIA(GPU-0): 
[  5433.076] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  5433.076] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  5433.076] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  5433.076] (--) NVIDIA(GPU-0): 
[  5433.139] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5433.139] (II) AMDGPU(0): Using hsync ranges from config file
[  5433.139] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5433.139] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5433.139] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5433.139] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5433.141] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5433.141] (II) AMDGPU(0): Using hsync ranges from config file
[  5433.141] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5433.141] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5433.141] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5433.141] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5433.141] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  5433.141] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  5433.141] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  5433.141] (--) NVIDIA(GPU-0): 
[  5433.141] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  5433.141] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  5433.141] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  5433.141] (--) NVIDIA(GPU-0): 
[  5433.346] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5433.346] (II) AMDGPU(0): Using hsync ranges from config file
[  5433.346] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5433.346] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5433.346] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5433.347] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5433.348] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5433.351] (II) AMDGPU(0): Allocate new frame buffer 5760x2160
[  5433.351] (II) AMDGPU(0):  => pitch 23040 bytes
[  5433.462] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5433.462] (II) AMDGPU(0): Using hsync ranges from config file
[  5433.462] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5433.462] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5433.462] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5433.462] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5433.463] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5433.465] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5433.465] (II) AMDGPU(0): Using hsync ranges from config file
[  5433.465] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5433.465] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5433.465] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5433.465] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5433.466] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5433.466] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  5433.466] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  5433.467] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  5433.467] (--) NVIDIA(GPU-0): 
[  5433.467] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  5433.467] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  5433.467] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  5433.467] (--) NVIDIA(GPU-0): 
[  5433.624] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5433.624] (II) AMDGPU(0): Using hsync ranges from config file
[  5433.624] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5433.624] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5433.624] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5433.624] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5433.625] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5433.627] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5433.627] (II) AMDGPU(0): Using hsync ranges from config file
[  5433.627] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5433.627] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5433.627] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5433.627] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5433.628] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5433.628] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  5433.629] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  5433.629] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  5433.629] (--) NVIDIA(GPU-0): 
[  5433.629] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  5433.629] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  5433.629] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  5433.629] (--) NVIDIA(GPU-0): 
[  5433.701] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5433.701] (II) AMDGPU(0): Using hsync ranges from config file
[  5433.701] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5433.701] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5433.701] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5433.701] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5433.702] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5433.704] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5433.704] (II) AMDGPU(0): Using hsync ranges from config file
[  5433.704] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5433.704] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5433.704] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5433.704] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5433.705] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5433.705] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  5433.705] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  5433.705] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  5433.705] (--) NVIDIA(GPU-0): 
[  5433.705] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  5433.705] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  5433.705] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  5433.705] (--) NVIDIA(GPU-0): 
[  5504.167] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5504.167] (II) AMDGPU(0): Using hsync ranges from config file
[  5504.167] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5504.167] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5504.167] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5504.167] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5504.173] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5504.173] (II) AMDGPU(0): Using hsync ranges from config file
[  5504.173] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5504.173] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5504.174] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5504.174] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5504.176] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5504.176] (II) AMDGPU(0): Using hsync ranges from config file
[  5504.176] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5504.176] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5504.176] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5504.176] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5504.176] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  5504.176] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  5504.176] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  5504.176] (--) NVIDIA(GPU-0): 
[  5504.176] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  5504.176] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  5504.176] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  5504.176] (--) NVIDIA(GPU-0): 
[  5504.287] (EE) AMDGPU(0): drmmode_do_crtc_dpms cannot get last vblank counter
[  5504.287] (II) AMDGPU(0): Allocate new frame buffer 1920x1080
[  5504.288] (II) AMDGPU(0):  => pitch 7680 bytes
[  5504.328] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5504.328] (II) AMDGPU(0): Using hsync ranges from config file
[  5504.328] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5504.328] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5504.328] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5504.328] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5504.330] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5504.330] (II) AMDGPU(0): Using hsync ranges from config file
[  5504.330] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5504.330] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5504.330] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5504.330] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5504.330] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  5504.330] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  5504.330] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  5504.330] (--) NVIDIA(GPU-0): 
[  5504.331] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  5504.331] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  5504.331] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  5504.331] (--) NVIDIA(GPU-0): 
[  5504.393] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5504.393] (II) AMDGPU(0): Using hsync ranges from config file
[  5504.393] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5504.393] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5504.393] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5504.393] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5504.395] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5504.395] (II) AMDGPU(0): Using hsync ranges from config file
[  5504.395] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5504.395] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5504.395] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5504.395] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5504.395] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  5504.395] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  5504.395] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  5504.395] (--) NVIDIA(GPU-0): 
[  5504.395] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  5504.395] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  5504.395] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  5504.395] (--) NVIDIA(GPU-0): 
[  5504.606] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5504.606] (II) AMDGPU(0): Using hsync ranges from config file
[  5504.606] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5504.606] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5504.606] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5504.606] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5504.608] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5504.611] (II) AMDGPU(0): Allocate new frame buffer 5760x2160
[  5504.611] (II) AMDGPU(0):  => pitch 23040 bytes
[  5504.715] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5504.715] (II) AMDGPU(0): Using hsync ranges from config file
[  5504.715] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5504.715] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5504.715] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5504.715] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5504.716] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5504.718] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5504.718] (II) AMDGPU(0): Using hsync ranges from config file
[  5504.718] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5504.718] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5504.718] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5504.718] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5504.720] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5504.720] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  5504.720] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  5504.720] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  5504.720] (--) NVIDIA(GPU-0): 
[  5504.720] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  5504.720] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  5504.720] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  5504.720] (--) NVIDIA(GPU-0): 
[  5504.873] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5504.873] (II) AMDGPU(0): Using hsync ranges from config file
[  5504.873] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5504.873] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5504.873] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5504.873] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5504.874] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5504.877] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5504.877] (II) AMDGPU(0): Using hsync ranges from config file
[  5504.877] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5504.877] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5504.877] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5504.877] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5504.878] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5504.878] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  5504.878] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  5504.878] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  5504.878] (--) NVIDIA(GPU-0): 
[  5504.879] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  5504.879] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  5504.879] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  5504.879] (--) NVIDIA(GPU-0): 
[  5504.949] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5504.949] (II) AMDGPU(0): Using hsync ranges from config file
[  5504.949] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5504.949] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5504.949] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5504.949] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5504.951] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5504.953] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5504.953] (II) AMDGPU(0): Using hsync ranges from config file
[  5504.953] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5504.953] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5504.953] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5504.953] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5504.954] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5504.954] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  5504.954] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  5504.954] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  5504.954] (--) NVIDIA(GPU-0): 
[  5504.954] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  5504.954] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  5504.954] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  5504.954] (--) NVIDIA(GPU-0): 
[  5600.267] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5600.267] (II) AMDGPU(0): Using hsync ranges from config file
[  5600.267] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5600.267] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5600.267] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5600.267] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5600.289] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5600.289] (II) AMDGPU(0): Using hsync ranges from config file
[  5600.289] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5600.289] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5600.289] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5600.289] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5600.291] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5600.291] (II) AMDGPU(0): Using hsync ranges from config file
[  5600.291] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5600.291] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5600.291] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5600.291] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5600.291] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  5600.291] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  5600.291] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  5600.291] (--) NVIDIA(GPU-0): 
[  5600.291] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  5600.291] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  5600.291] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  5600.291] (--) NVIDIA(GPU-0): 
[  5600.422] (EE) AMDGPU(0): drmmode_do_crtc_dpms cannot get last vblank counter
[  5600.422] (II) AMDGPU(0): Allocate new frame buffer 1920x1080
[  5600.423] (II) AMDGPU(0):  => pitch 7680 bytes
[  5600.458] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5600.458] (II) AMDGPU(0): Using hsync ranges from config file
[  5600.458] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5600.458] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5600.458] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5600.458] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5600.460] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5600.460] (II) AMDGPU(0): Using hsync ranges from config file
[  5600.460] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5600.460] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5600.460] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5600.460] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5600.460] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  5600.460] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  5600.460] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  5600.460] (--) NVIDIA(GPU-0): 
[  5600.460] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  5600.460] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  5600.460] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  5600.460] (--) NVIDIA(GPU-0): 
[  5600.536] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5600.536] (II) AMDGPU(0): Using hsync ranges from config file
[  5600.536] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5600.536] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5600.536] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5600.536] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5600.538] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5600.538] (II) AMDGPU(0): Using hsync ranges from config file
[  5600.538] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5600.538] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5600.538] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5600.538] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5600.538] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  5600.538] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  5600.538] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  5600.538] (--) NVIDIA(GPU-0): 
[  5600.538] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  5600.538] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  5600.538] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  5600.538] (--) NVIDIA(GPU-0): 
[  5600.705] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5600.705] (II) AMDGPU(0): Using hsync ranges from config file
[  5600.705] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5600.705] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5600.705] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5600.705] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5600.708] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5600.711] (II) AMDGPU(0): Allocate new frame buffer 5760x2160
[  5600.711] (II) AMDGPU(0):  => pitch 23040 bytes
[  5600.807] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5600.807] (II) AMDGPU(0): Using hsync ranges from config file
[  5600.807] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5600.807] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5600.807] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5600.807] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5600.808] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5600.810] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5600.810] (II) AMDGPU(0): Using hsync ranges from config file
[  5600.810] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5600.810] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5600.810] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5600.810] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5600.812] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5600.812] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  5600.812] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  5600.812] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  5600.812] (--) NVIDIA(GPU-0): 
[  5600.812] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  5600.812] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  5600.812] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  5600.812] (--) NVIDIA(GPU-0): 
[  5600.967] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5600.967] (II) AMDGPU(0): Using hsync ranges from config file
[  5600.967] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5600.967] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5600.967] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5600.967] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5600.969] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5600.971] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5600.971] (II) AMDGPU(0): Using hsync ranges from config file
[  5600.971] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5600.971] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5600.971] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5600.971] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5600.973] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5600.973] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  5600.973] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  5600.973] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  5600.973] (--) NVIDIA(GPU-0): 
[  5600.973] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  5600.973] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  5600.973] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  5600.973] (--) NVIDIA(GPU-0): 
[  5601.037] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5601.037] (II) AMDGPU(0): Using hsync ranges from config file
[  5601.037] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5601.037] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5601.037] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5601.037] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5601.039] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5601.040] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  5601.040] (II) AMDGPU(0): Using hsync ranges from config file
[  5601.040] (II) AMDGPU(0): Using vrefresh ranges from config file
[  5601.040] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  5601.040] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  5601.040] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  5601.042] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  5601.042] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  5601.042] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  5601.042] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  5601.042] (--) NVIDIA(GPU-0): 
[  5601.042] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  5601.042] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  5601.042] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  5601.042] (--) NVIDIA(GPU-0): 
[  9834.423] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  9834.423] (II) AMDGPU(0): Using hsync ranges from config file
[  9834.423] (II) AMDGPU(0): Using vrefresh ranges from config file
[  9834.423] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  9834.423] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  9834.423] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  9834.429] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  9834.429] (II) AMDGPU(0): Using hsync ranges from config file
[  9834.429] (II) AMDGPU(0): Using vrefresh ranges from config file
[  9834.429] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  9834.429] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  9834.429] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  9834.431] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  9834.431] (II) AMDGPU(0): Using hsync ranges from config file
[  9834.431] (II) AMDGPU(0): Using vrefresh ranges from config file
[  9834.431] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  9834.431] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  9834.431] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  9834.431] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  9834.431] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  9834.431] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  9834.431] (--) NVIDIA(GPU-0): 
[  9834.431] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  9834.431] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  9834.431] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  9834.431] (--) NVIDIA(GPU-0): 
[  9834.552] (EE) AMDGPU(0): drmmode_do_crtc_dpms cannot get last vblank counter
[  9834.553] (II) AMDGPU(0): Allocate new frame buffer 1920x1080
[  9834.553] (II) AMDGPU(0):  => pitch 7680 bytes
[  9834.589] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  9834.589] (II) AMDGPU(0): Using hsync ranges from config file
[  9834.589] (II) AMDGPU(0): Using vrefresh ranges from config file
[  9834.589] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  9834.589] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  9834.589] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  9834.591] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  9834.591] (II) AMDGPU(0): Using hsync ranges from config file
[  9834.591] (II) AMDGPU(0): Using vrefresh ranges from config file
[  9834.591] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  9834.591] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  9834.591] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  9834.592] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  9834.592] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  9834.592] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  9834.592] (--) NVIDIA(GPU-0): 
[  9834.592] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  9834.592] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  9834.592] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  9834.592] (--) NVIDIA(GPU-0): 
[  9834.658] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  9834.658] (II) AMDGPU(0): Using hsync ranges from config file
[  9834.658] (II) AMDGPU(0): Using vrefresh ranges from config file
[  9834.658] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  9834.658] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  9834.658] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  9834.660] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  9834.660] (II) AMDGPU(0): Using hsync ranges from config file
[  9834.660] (II) AMDGPU(0): Using vrefresh ranges from config file
[  9834.660] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  9834.660] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  9834.660] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  9834.660] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  9834.660] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  9834.660] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  9834.660] (--) NVIDIA(GPU-0): 
[  9834.660] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  9834.660] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  9834.660] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  9834.660] (--) NVIDIA(GPU-0): 
[  9834.899] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  9834.899] (II) AMDGPU(0): Using hsync ranges from config file
[  9834.899] (II) AMDGPU(0): Using vrefresh ranges from config file
[  9834.899] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  9834.899] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  9834.899] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  9834.900] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  9834.903] (II) AMDGPU(0): Allocate new frame buffer 5760x2160
[  9834.904] (II) AMDGPU(0):  => pitch 23040 bytes
[  9835.034] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  9835.035] (II) AMDGPU(0): Using hsync ranges from config file
[  9835.035] (II) AMDGPU(0): Using vrefresh ranges from config file
[  9835.035] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  9835.035] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  9835.035] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  9835.036] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  9835.038] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  9835.038] (II) AMDGPU(0): Using hsync ranges from config file
[  9835.038] (II) AMDGPU(0): Using vrefresh ranges from config file
[  9835.038] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  9835.038] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  9835.038] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  9835.039] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  9835.039] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  9835.039] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  9835.039] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  9835.039] (--) NVIDIA(GPU-0): 
[  9835.039] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  9835.039] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  9835.039] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  9835.039] (--) NVIDIA(GPU-0): 
[  9835.227] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  9835.227] (II) AMDGPU(0): Using hsync ranges from config file
[  9835.227] (II) AMDGPU(0): Using vrefresh ranges from config file
[  9835.227] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  9835.227] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  9835.227] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  9835.228] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  9835.230] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  9835.230] (II) AMDGPU(0): Using hsync ranges from config file
[  9835.230] (II) AMDGPU(0): Using vrefresh ranges from config file
[  9835.230] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  9835.230] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  9835.230] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  9835.232] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  9835.232] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  9835.232] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  9835.232] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  9835.232] (--) NVIDIA(GPU-0): 
[  9835.232] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  9835.232] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  9835.232] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  9835.232] (--) NVIDIA(GPU-0): 
[  9835.304] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  9835.304] (II) AMDGPU(0): Using hsync ranges from config file
[  9835.304] (II) AMDGPU(0): Using vrefresh ranges from config file
[  9835.304] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  9835.304] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  9835.304] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  9835.306] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  9835.308] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[  9835.308] (II) AMDGPU(0): Using hsync ranges from config file
[  9835.308] (II) AMDGPU(0): Using vrefresh ranges from config file
[  9835.308] (II) AMDGPU(0): Printing DDC gathered Modelines:
[  9835.308] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[  9835.308] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[  9835.310] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[  9835.310] (--) NVIDIA(GPU-0): DFP-0: disconnected
[  9835.310] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[  9835.310] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[  9835.310] (--) NVIDIA(GPU-0): 
[  9835.310] (--) NVIDIA(GPU-0): DFP-1: disconnected
[  9835.310] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[  9835.310] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[  9835.310] (--) NVIDIA(GPU-0): 
[ 10082.465] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10082.465] (II) AMDGPU(0): Using hsync ranges from config file
[ 10082.465] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10082.465] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10082.465] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10082.465] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10082.471] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10082.471] (II) AMDGPU(0): Using hsync ranges from config file
[ 10082.471] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10082.471] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10082.471] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10082.471] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10082.473] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10082.473] (II) AMDGPU(0): Using hsync ranges from config file
[ 10082.473] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10082.473] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10082.473] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10082.473] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10082.473] (--) NVIDIA(GPU-0): DFP-0: disconnected
[ 10082.473] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[ 10082.473] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[ 10082.473] (--) NVIDIA(GPU-0): 
[ 10082.473] (--) NVIDIA(GPU-0): DFP-1: disconnected
[ 10082.473] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[ 10082.473] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[ 10082.473] (--) NVIDIA(GPU-0): 
[ 10082.587] (EE) AMDGPU(0): drmmode_do_crtc_dpms cannot get last vblank counter
[ 10082.588] (II) AMDGPU(0): Allocate new frame buffer 1920x1080
[ 10082.588] (II) AMDGPU(0):  => pitch 7680 bytes
[ 10082.617] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10082.617] (II) AMDGPU(0): Using hsync ranges from config file
[ 10082.617] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10082.617] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10082.617] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10082.617] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10082.619] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10082.619] (II) AMDGPU(0): Using hsync ranges from config file
[ 10082.619] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10082.619] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10082.619] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10082.619] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10082.619] (--) NVIDIA(GPU-0): DFP-0: disconnected
[ 10082.619] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[ 10082.619] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[ 10082.619] (--) NVIDIA(GPU-0): 
[ 10082.620] (--) NVIDIA(GPU-0): DFP-1: disconnected
[ 10082.620] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[ 10082.620] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[ 10082.620] (--) NVIDIA(GPU-0): 
[ 10082.666] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10082.666] (II) AMDGPU(0): Using hsync ranges from config file
[ 10082.666] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10082.666] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10082.667] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10082.667] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10082.669] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10082.669] (II) AMDGPU(0): Using hsync ranges from config file
[ 10082.669] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10082.669] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10082.669] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10082.669] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10082.669] (--) NVIDIA(GPU-0): DFP-0: disconnected
[ 10082.669] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[ 10082.669] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[ 10082.669] (--) NVIDIA(GPU-0): 
[ 10082.669] (--) NVIDIA(GPU-0): DFP-1: disconnected
[ 10082.669] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[ 10082.669] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[ 10082.669] (--) NVIDIA(GPU-0): 
[ 10082.910] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10082.910] (II) AMDGPU(0): Using hsync ranges from config file
[ 10082.910] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10082.910] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10082.910] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10082.910] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10082.912] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 10082.918] (II) AMDGPU(0): Allocate new frame buffer 5760x2160
[ 10082.919] (II) AMDGPU(0):  => pitch 23040 bytes
[ 10083.032] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10083.032] (II) AMDGPU(0): Using hsync ranges from config file
[ 10083.032] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10083.032] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10083.032] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10083.032] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10083.033] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 10083.035] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10083.035] (II) AMDGPU(0): Using hsync ranges from config file
[ 10083.035] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10083.035] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10083.035] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10083.035] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10083.037] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 10083.037] (--) NVIDIA(GPU-0): DFP-0: disconnected
[ 10083.037] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[ 10083.037] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[ 10083.037] (--) NVIDIA(GPU-0): 
[ 10083.037] (--) NVIDIA(GPU-0): DFP-1: disconnected
[ 10083.037] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[ 10083.037] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[ 10083.037] (--) NVIDIA(GPU-0): 
[ 10083.187] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10083.188] (II) AMDGPU(0): Using hsync ranges from config file
[ 10083.188] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10083.188] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10083.188] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10083.188] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10083.189] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 10083.191] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10083.191] (II) AMDGPU(0): Using hsync ranges from config file
[ 10083.191] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10083.191] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10083.191] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10083.191] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10083.193] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 10083.193] (--) NVIDIA(GPU-0): DFP-0: disconnected
[ 10083.193] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[ 10083.193] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[ 10083.193] (--) NVIDIA(GPU-0): 
[ 10083.193] (--) NVIDIA(GPU-0): DFP-1: disconnected
[ 10083.193] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[ 10083.193] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[ 10083.193] (--) NVIDIA(GPU-0): 
[ 10083.265] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10083.265] (II) AMDGPU(0): Using hsync ranges from config file
[ 10083.265] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10083.265] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10083.265] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10083.265] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10083.267] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 10083.269] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10083.269] (II) AMDGPU(0): Using hsync ranges from config file
[ 10083.269] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10083.269] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10083.269] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10083.269] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10083.271] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 10083.271] (--) NVIDIA(GPU-0): DFP-0: disconnected
[ 10083.271] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[ 10083.271] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[ 10083.271] (--) NVIDIA(GPU-0): 
[ 10083.271] (--) NVIDIA(GPU-0): DFP-1: disconnected
[ 10083.271] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[ 10083.271] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[ 10083.271] (--) NVIDIA(GPU-0): 
[ 10876.336] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10876.336] (II) AMDGPU(0): Using hsync ranges from config file
[ 10876.336] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10876.336] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10876.336] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10876.336] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10876.348] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10876.348] (II) AMDGPU(0): Using hsync ranges from config file
[ 10876.348] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10876.348] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10876.348] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10876.348] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10876.350] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10876.350] (II) AMDGPU(0): Using hsync ranges from config file
[ 10876.350] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10876.350] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10876.350] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10876.350] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10876.350] (--) NVIDIA(GPU-0): DFP-0: disconnected
[ 10876.350] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[ 10876.350] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[ 10876.350] (--) NVIDIA(GPU-0): 
[ 10876.350] (--) NVIDIA(GPU-0): DFP-1: disconnected
[ 10876.350] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[ 10876.350] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[ 10876.350] (--) NVIDIA(GPU-0): 
[ 10876.459] (EE) AMDGPU(0): drmmode_do_crtc_dpms cannot get last vblank counter
[ 10876.459] (II) AMDGPU(0): Allocate new frame buffer 1920x1080
[ 10876.459] (II) AMDGPU(0):  => pitch 7680 bytes
[ 10876.498] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10876.498] (II) AMDGPU(0): Using hsync ranges from config file
[ 10876.498] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10876.498] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10876.498] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10876.498] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10876.500] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10876.500] (II) AMDGPU(0): Using hsync ranges from config file
[ 10876.500] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10876.500] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10876.500] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10876.500] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10876.500] (--) NVIDIA(GPU-0): DFP-0: disconnected
[ 10876.500] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[ 10876.500] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[ 10876.500] (--) NVIDIA(GPU-0): 
[ 10876.500] (--) NVIDIA(GPU-0): DFP-1: disconnected
[ 10876.500] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[ 10876.500] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[ 10876.500] (--) NVIDIA(GPU-0): 
[ 10876.561] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10876.561] (II) AMDGPU(0): Using hsync ranges from config file
[ 10876.561] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10876.561] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10876.561] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10876.561] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10876.563] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10876.563] (II) AMDGPU(0): Using hsync ranges from config file
[ 10876.563] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10876.563] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10876.563] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10876.563] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10876.563] (--) NVIDIA(GPU-0): DFP-0: disconnected
[ 10876.563] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[ 10876.563] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[ 10876.563] (--) NVIDIA(GPU-0): 
[ 10876.563] (--) NVIDIA(GPU-0): DFP-1: disconnected
[ 10876.563] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[ 10876.563] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[ 10876.563] (--) NVIDIA(GPU-0): 
[ 10876.780] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10876.781] (II) AMDGPU(0): Using hsync ranges from config file
[ 10876.781] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10876.781] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10876.781] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10876.781] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10876.782] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 10876.785] (II) AMDGPU(0): Allocate new frame buffer 5760x2160
[ 10876.785] (II) AMDGPU(0):  => pitch 23040 bytes
[ 10876.897] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10876.897] (II) AMDGPU(0): Using hsync ranges from config file
[ 10876.897] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10876.897] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10876.897] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10876.897] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10876.898] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 10876.900] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10876.900] (II) AMDGPU(0): Using hsync ranges from config file
[ 10876.900] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10876.900] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10876.900] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10876.900] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10876.901] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 10876.901] (--) NVIDIA(GPU-0): DFP-0: disconnected
[ 10876.901] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[ 10876.901] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[ 10876.901] (--) NVIDIA(GPU-0): 
[ 10876.901] (--) NVIDIA(GPU-0): DFP-1: disconnected
[ 10876.901] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[ 10876.901] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[ 10876.901] (--) NVIDIA(GPU-0): 
[ 10877.057] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10877.057] (II) AMDGPU(0): Using hsync ranges from config file
[ 10877.057] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10877.057] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10877.058] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10877.058] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10877.059] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 10877.061] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10877.061] (II) AMDGPU(0): Using hsync ranges from config file
[ 10877.061] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10877.061] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10877.061] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10877.061] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10877.062] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 10877.062] (--) NVIDIA(GPU-0): DFP-0: disconnected
[ 10877.062] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[ 10877.062] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[ 10877.062] (--) NVIDIA(GPU-0): 
[ 10877.062] (--) NVIDIA(GPU-0): DFP-1: disconnected
[ 10877.062] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[ 10877.062] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[ 10877.062] (--) NVIDIA(GPU-0): 
[ 10877.135] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10877.135] (II) AMDGPU(0): Using hsync ranges from config file
[ 10877.135] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10877.135] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10877.135] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10877.135] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10877.136] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 10877.138] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 10877.138] (II) AMDGPU(0): Using hsync ranges from config file
[ 10877.138] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 10877.138] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 10877.138] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 10877.138] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 10877.140] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 10877.140] (--) NVIDIA(GPU-0): DFP-0: disconnected
[ 10877.140] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[ 10877.140] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[ 10877.140] (--) NVIDIA(GPU-0): 
[ 10877.140] (--) NVIDIA(GPU-0): DFP-1: disconnected
[ 10877.140] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[ 10877.140] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[ 10877.140] (--) NVIDIA(GPU-0): 
[ 11275.953] (EE) event19 - Logitech Wireless Mouse: client bug: event processing lagging behind by 22ms, your system is too slow
[ 23658.197] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 23658.197] (II) AMDGPU(0): Using hsync ranges from config file
[ 23658.197] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 23658.197] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 23658.197] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 23658.197] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 23658.212] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 23658.212] (II) AMDGPU(0): Using hsync ranges from config file
[ 23658.212] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 23658.212] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 23658.212] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 23658.212] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 23658.214] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 23658.214] (II) AMDGPU(0): Using hsync ranges from config file
[ 23658.214] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 23658.214] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 23658.214] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 23658.214] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 23658.215] (--) NVIDIA(GPU-0): DFP-0: disconnected
[ 23658.215] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[ 23658.215] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[ 23658.215] (--) NVIDIA(GPU-0): 
[ 23658.215] (--) NVIDIA(GPU-0): DFP-1: disconnected
[ 23658.215] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[ 23658.215] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[ 23658.215] (--) NVIDIA(GPU-0): 
[ 23658.350] (EE) AMDGPU(0): drmmode_do_crtc_dpms cannot get last vblank counter
[ 23658.351] (II) AMDGPU(0): Allocate new frame buffer 1920x1080
[ 23658.351] (II) AMDGPU(0):  => pitch 7680 bytes
[ 23658.376] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 23658.376] (II) AMDGPU(0): Using hsync ranges from config file
[ 23658.376] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 23658.376] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 23658.376] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 23658.376] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 23658.378] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 23658.378] (II) AMDGPU(0): Using hsync ranges from config file
[ 23658.378] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 23658.378] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 23658.378] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 23658.378] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 23658.379] (--) NVIDIA(GPU-0): DFP-0: disconnected
[ 23658.379] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[ 23658.379] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[ 23658.379] (--) NVIDIA(GPU-0): 
[ 23658.379] (--) NVIDIA(GPU-0): DFP-1: disconnected
[ 23658.379] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[ 23658.379] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[ 23658.379] (--) NVIDIA(GPU-0): 
[ 23658.459] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 23658.459] (II) AMDGPU(0): Using hsync ranges from config file
[ 23658.459] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 23658.459] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 23658.459] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 23658.459] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 23658.462] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 23658.462] (II) AMDGPU(0): Using hsync ranges from config file
[ 23658.462] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 23658.462] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 23658.462] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 23658.462] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 23658.462] (--) NVIDIA(GPU-0): DFP-0: disconnected
[ 23658.462] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[ 23658.462] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[ 23658.462] (--) NVIDIA(GPU-0): 
[ 23658.462] (--) NVIDIA(GPU-0): DFP-1: disconnected
[ 23658.462] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[ 23658.462] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[ 23658.462] (--) NVIDIA(GPU-0): 
[ 23658.668] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 23658.668] (II) AMDGPU(0): Using hsync ranges from config file
[ 23658.668] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 23658.668] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 23658.668] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 23658.668] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 23658.669] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 23658.672] (II) AMDGPU(0): Allocate new frame buffer 5760x2160
[ 23658.672] (II) AMDGPU(0):  => pitch 23040 bytes
[ 23658.783] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 23658.783] (II) AMDGPU(0): Using hsync ranges from config file
[ 23658.783] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 23658.783] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 23658.783] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 23658.783] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 23658.784] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 23658.786] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 23658.786] (II) AMDGPU(0): Using hsync ranges from config file
[ 23658.786] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 23658.786] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 23658.786] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 23658.786] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 23658.787] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 23658.787] (--) NVIDIA(GPU-0): DFP-0: disconnected
[ 23658.787] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[ 23658.787] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[ 23658.787] (--) NVIDIA(GPU-0): 
[ 23658.788] (--) NVIDIA(GPU-0): DFP-1: disconnected
[ 23658.788] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[ 23658.788] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[ 23658.788] (--) NVIDIA(GPU-0): 
[ 23658.950] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 23658.950] (II) AMDGPU(0): Using hsync ranges from config file
[ 23658.950] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 23658.950] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 23658.950] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 23658.950] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 23658.951] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 23658.953] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 23658.953] (II) AMDGPU(0): Using hsync ranges from config file
[ 23658.953] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 23658.953] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 23658.953] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 23658.953] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 23658.955] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 23658.955] (--) NVIDIA(GPU-0): DFP-0: disconnected
[ 23658.955] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[ 23658.955] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[ 23658.955] (--) NVIDIA(GPU-0): 
[ 23658.955] (--) NVIDIA(GPU-0): DFP-1: disconnected
[ 23658.955] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[ 23658.955] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[ 23658.955] (--) NVIDIA(GPU-0): 
[ 23658.998] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 23658.998] (II) AMDGPU(0): Using hsync ranges from config file
[ 23658.998] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 23658.998] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 23658.998] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 23658.998] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 23658.999] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 23659.001] (II) AMDGPU(0): EDID vendor "NCP", prod id 77
[ 23659.001] (II) AMDGPU(0): Using hsync ranges from config file
[ 23659.001] (II) AMDGPU(0): Using vrefresh ranges from config file
[ 23659.001] (II) AMDGPU(0): Printing DDC gathered Modelines:
[ 23659.001] (II) AMDGPU(0): Modeline "1920x1080"x0.0  354.73  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (162.7 kHz eP)
[ 23659.001] (II) AMDGPU(0): Modeline "1920x1080"x0.0  147.81  1920 1968 2000 2180  1080 1083 1088 1130 +hsync -vsync (67.8 kHz e)
[ 23659.003] (--) AMDGPU(0): HDMI max TMDS frequency 300000KHz
[ 23659.003] (--) NVIDIA(GPU-0): DFP-0: disconnected
[ 23659.003] (--) NVIDIA(GPU-0): DFP-0: Internal DisplayPort
[ 23659.003] (--) NVIDIA(GPU-0): DFP-0: 2670.0 MHz maximum pixel clock
[ 23659.003] (--) NVIDIA(GPU-0): 
[ 23659.003] (--) NVIDIA(GPU-0): DFP-1: disconnected
[ 23659.003] (--) NVIDIA(GPU-0): DFP-1: Internal TMDS
[ 23659.003] (--) NVIDIA(GPU-0): DFP-1: 165.0 MHz maximum pixel clock
[ 23659.003] (--) NVIDIA(GPU-0): 
[ 23664.542] (EE) event18 - Logitech Wireless Keyboard PID:4023: client bug: event processing lagging behind by 36ms, your system is too slow
[ 23730.347] (EE) event19 - Logitech Wireless Mouse: client bug: event processing lagging behind by 26ms, your system is too slow
[ 26616.702] (**) Option "fd" "49"
[ 26616.702] (II) event4  - Asus Wireless Radio Control: device removed
[ 26616.703] (**) Option "fd" "52"
[ 26616.703] (II) event5  - Video Bus: device removed
[ 26616.703] (**) Option "fd" "53"
[ 26616.703] (II) event6  - Video Bus: device removed
[ 26616.703] (**) Option "fd" "54"
[ 26616.703] (II) event0  - Power Button: device removed
[ 26616.703] (**) Option "fd" "55"
[ 26616.703] (II) event1  - Sleep Button: device removed
[ 26616.703] (**) Option "fd" "56"
[ 26616.703] (**) Option "fd" "57"
[ 26616.703] (II) event19 - Logitech Wireless Mouse: device removed
[ 26616.703] (**) Option "fd" "58"
[ 26616.703] (II) event11 - USB2.0 HD UVC WebCam: USB2.0 HD: device removed
[ 26616.703] (**) Option "fd" "59"
[ 26616.703] (II) event12 - ELAN1203:00 04F3:307A Mouse: device removed
[ 26616.704] (**) Option "fd" "60"
[ 26616.704] (II) event13 - ELAN1203:00 04F3:307A Touchpad: device removed
[ 26616.704] (**) Option "fd" "61"
[ 26616.704] (II) event14 - Asus WMI hotkeys: device removed
[ 26616.704] (**) Option "fd" "62"
[ 26616.704] (II) event3  - AT Translated Set 2 keyboard: device removed
[ 26616.704] (**) Option "fd" "56"
[ 26616.704] (II) event18 - Logitech Wireless Keyboard PID:4023: device removed
[ 26617.895] (II) UnloadModule: "libinput"
[ 26617.896] (II) systemd-logind: not releasing fd for 13:82, still in use
[ 26617.896] (II) UnloadModule: "libinput"
[ 26617.896] (II) systemd-logind: releasing fd for 13:67
[ 26617.909] (II) UnloadModule: "libinput"
[ 26617.909] (II) systemd-logind: releasing fd for 13:78
[ 26617.949] (II) UnloadModule: "libinput"
[ 26617.949] (II) systemd-logind: releasing fd for 13:77
[ 26617.989] (II) UnloadModule: "libinput"
[ 26617.989] (II) systemd-logind: releasing fd for 13:76
[ 26618.029] (II) UnloadModule: "libinput"
[ 26618.029] (II) systemd-logind: releasing fd for 13:75
[ 26618.066] (II) UnloadModule: "libinput"
[ 26618.066] (II) systemd-logind: releasing fd for 13:83
[ 26618.109] (II) UnloadModule: "libinput"
[ 26618.109] (II) systemd-logind: releasing fd for 13:82
[ 26618.126] (II) UnloadModule: "libinput"
[ 26618.126] (II) systemd-logind: releasing fd for 13:65
[ 26618.149] (II) UnloadModule: "libinput"
[ 26618.149] (II) systemd-logind: releasing fd for 13:64
[ 26618.176] (II) UnloadModule: "libinput"
[ 26618.176] (II) systemd-logind: releasing fd for 13:70
[ 26618.215] (II) UnloadModule: "libinput"
[ 26618.215] (II) systemd-logind: releasing fd for 13:69
[ 26618.216] (II) UnloadModule: "libinput"
[ 26618.216] (II) systemd-logind: releasing fd for 13:68
[ 26618.252] (II) NVIDIA(GPU-0): Deleting GPU-0
[ 26618.255] (WW) xf86CloseConsole: KDSETMODE failed: Input/output error
[ 26618.255] (WW) xf86CloseConsole: VT_GETMODE failed: Input/output error
[ 26618.371] (II) Server terminated successfully (0). Closing log file.

____________________________________________

*** /usr/share/nvidia/nvidia-application-profiles-520.56.06-rc
*** ls: -rw-r--r-- 1 root root 9649 2022-10-12 13:15:44.000000000 -0300 /usr/share/nvidia/nvidia-application-profiles-520.56.06-rc
# Application profiles for the NVIDIA Linux graphics driver, version 520.56.06
# Last modified: Thu Oct  6 21:20:40 UTC 2022
# These profiles were provided by NVIDIA and should not be modified.  If you
# wish to change the defaults provided here, you can override them by creating
# custom rules in /etc/nvidia/nvidia-application-profiles-rc (which will apply
# system-wide) or, for a given user, $HOME/.nv/nvidia-application-profiles-rc
# (which will apply to that particular user). See the "APPLICATION PROFILE
# SEARCH PATH" section of the NVIDIA Linux Graphics Driver README for more
# information.
{
    "profiles" : [
        {
          "name" : "NonConformantBlitFramebufferScissor",
          "settings" : [ "GLConformantBlitFramebufferScissor", false ]
        },
        {
          "name" : "CL1C",
          "settings" : [ "0x528ab3", 1 ]
        },
        {
          "name" : "FA0",
          "settings" : [ "10572898", 0 ]
        },
        {
          "name" : "ExactGLESVersion",
          "settings" : [ "ForceRequestedESVersion", 1 ]
        },
        {
          "name" : "IgnoreGLSLExtensionRequirements",
          "settings" : [ "GLIgnoreGLSLExtReqs", true ]
        },
        {
          "name" : "No VRR/OSD",
          "settings" : [
            {
              "key"   : "GLVRRAllowed",
              "value" : false
            },
            {
              "key"   : "VKDirectGSYNCAllowed",
              "value" : false
            },
            {
              "key"   : "VKDirectGSYNCCompatibleAllowed",
              "value" : 0
            },
            {
              "key"   : "GLShowGraphicsOSD",
              "value" : false
            }
          ]
        },
        {
          "name" : "UseThreadedOptimizations",
          "settings" : [ "GLThreadedOptimizations", true ]
        },
        {
          "name" : "NoThreadedOptimizations",
          "settings" : [ "GLThreadedOptimizations", false ]
        },
        {
          "name" : "NoAniso",
          "settings" : [ "GLLogMaxAniso", 0 ]
        },
        {
          "name" : "NamedVertexAttributesApplyDivisor",
          "settings" : [ "GL23cd0e", 1 ]
        },
        {
        "name" : "NonStrictDrawRangeElements",
        "settings" : [ "GLStrictDrawRangeElements", false ]
        },
        {
          "name" : "NoEnforceShaderInputOutputMatching",
          "settings" : [ "GLShaderPortabilityWarnings", false ]
        },
        {
          "name" : "HideVendorID",
          "settings" : [ "OVERRIDE_VENDORID", 4098 ]
        },
        {
          "name" : "DisablePersampleFragcoord",
          "settings" : [ "DisablePersampleFragcoord", true ]
        },
        {
          "name" : "ForceSeparateTrimThread",
          "settings" : [ "__GL_CPMM", 3 ]
        },
        {
            "name" : "IdleQueueOnSwapchainOOD",
            "settings" : [ "IdleQueueOnSwapchainOOD", true ]
        },
        {
            "name" : "DisableHostVisibleVidmem",
            "settings" : [ "HostVisibleVidmem", false ]
        },
        {
            "name" : "DedicatedHwStatePerCtx",
            "settings" : [ "HWSTATE_PER_CTX", true ]
        },
        {
            "name" : "OclCompuBenchRemoveConstArgWar",
            "settings" : [ "0x306c59", 1 ]
        }
    ],
    "rules" : [
        {
          "pattern" : {
             "feature" : "dso",
             "matches" : "libcogl.so"
          },
          "profile" : "NonConformantBlitFramebufferScissor"
        },
        {
          "pattern" : {
            "feature" : "dso",
            "matches" : "libMaya.so"
          },
          "profile" : "CL1C"
        },
        {
          "pattern" : {
            "feature" : "dso",
            "matches" : "libMaya.so"
          },
          "profile" : "NamedVertexAttributesApplyDivisor"
        },
        { "pattern" : "SkullGirls.x86_64-pc-linux-gnu", "profile" : "NoAniso" },
        { "pattern" : "SkullGirls.i686-pc-linux-gnu", "profile" : "NoAniso" },
        { "pattern" : "Indivisible_Linux.i686-pc-linux-gnu", "profile" : "NoAniso" },
        { "pattern" : "dontstarve_steam",     "profile" : "NoAniso" }, 
        { "pattern" : "xsi", "profile" : "CL1C" },
        { "pattern" : "HoudiniFX", "profile" : "CL1C" },
        { "pattern" : "katana", "profile" : "CL1C" },
        { "pattern" : "Autodesk Mudbox 2014 64-bit", "profile" : "CL1C" },
        { "pattern" : "octane", "profile" : "CL1C" },
        { "pattern" : "Fusion64_6.4", "profile" : "CL1C" },
        { "pattern" : "Nuke7.0", "profile" : "CL1C" },
        { "pattern" : "vray.exe", "profile" : "CL1C" },
        { "pattern" : "vray.bin", "profile" : "CL1C" },
        { "pattern" : "kwin_gles", "profile" : "FA0" },
        { "pattern" : "kwin_gles", "profile" : "ExactGLESVersion" },
        {
           "pattern" : [
            { "feature" : "procname", "matches" : "heaven_x86"},
            { "op" : "not", "sub" : { "feature" : "findfile", "matches" : "browser_x86" } }
           ],
           "profile" : "IgnoreGLSLExtensionRequirements"
        },
        {
           "pattern" : [
            { "feature" : "procname", "matches" : "heaven_x64"},
            { "op" : "not", "sub" : { "feature" : "findfile", "matches" : "browser_x64" } }
           ],
           "profile" : "IgnoreGLSLExtensionRequirements"
        },
        { "pattern" : { "feature" : "procname", "matches" : "cinnamon" },               "profile" : "No VRR/OSD" },
        { "pattern" : { "feature" : "procname", "matches" : "compiz" },                 "profile" : "No VRR/OSD" },
        { "pattern" : { "feature" : "procname", "matches" : "compton" },                "profile" : "No VRR/OSD" },
        { "pattern" : { "feature" : "procname", "matches" : "enlightenment" },          "profile" : "No VRR/OSD" },
        { "pattern" : { "feature" : "procname", "matches" : "gnome-shell" },            "profile" : "No VRR/OSD" },
        { "pattern" : { "feature" : "procname", "matches" : "kscreenlocker_greet" },    "profile" : "No VRR/OSD" },
        { "pattern" : { "feature" : "procname", "matches" : "kwin" },                   "profile" : "No VRR/OSD" },
        { "pattern" : { "feature" : "procname", "matches" : "kwin_x11" },               "profile" : "No VRR/OSD" },
        { "pattern" : { "feature" : "procname", "matches" : "picom" },                  "profile" : "No VRR/OSD" },
        { "pattern" : { "feature" : "procname", "matches" : "plasmashell" },            "profile" : "No VRR/OSD" },
        { "pattern" : { "feature" : "procname", "matches" : "ksplashqml" },             "profile" : "No VRR/OSD" },
        { "pattern" : { "feature" : "procname", "matches" : "systemsettings5" },        "profile" : "No VRR/OSD" },
        { "pattern" : { "feature" : "procname", "matches" : "muffin" },                 "profile" : "No VRR/OSD" },
        { "pattern" : { "feature" : "dso",      "matches" : "libmutter" },              "profile" : "No VRR/OSD" },
        { "pattern" : { "feature" : "procname", "matches" : "steam" },                  "profile" : "No VRR/OSD" },
        { "pattern" : { "feature" : "procname", "matches" : "steamcompmgr" },           "profile" : "No VRR/OSD" },
        { "pattern" : { "feature" : "procname", "matches" : "vrmonitor" },              "profile" : "No VRR/OSD" },
        { "pattern" : { "feature" : "procname", "matches" : "compubench_cl-CLI" },
          "profile" : "OclCompuBenchRemoveConstArgWar"
        },
        { "pattern" : "GoatGame", "profile" : "NonStrictDrawRangeElements" },
        { "pattern" : "ShadowOfMordor",  "profile" : "NoEnforceShaderInputOutputMatching" },
        { "pattern" : "shotcut",         "profile" : "NoThreadedOptimizations" },
        { "pattern" : "MetroLL",         "profile" :  "NoThreadedOptimizations" },
        { "pattern" : "Borderlands2",    "profile" : "UseThreadedOptimizations" },
        { "pattern" : "BorderlandsPreSequel", "profile" : "UseThreadedOptimizations" },
        { "pattern": "AlienIsolation",   "profile" : "UseThreadedOptimizations" },
        { "pattern": "Civ6",             "profile" : "UseThreadedOptimizations" },
        { "pattern": "CivBE",            "profile" : "UseThreadedOptimizations" },
        { "pattern": "overlord.i386",    "profile" : "UseThreadedOptimizations" },
        { "pattern": "X-Plane-x86_64",   "profile" : "UseThreadedOptimizations" },
        { "pattern": "RocketLeague",     "profile" : "UseThreadedOptimizations" },
        { "pattern": "RocketLeague",     "profile" : "NoAniso" },
        { "pattern": "DeusExMD",         "profile" : "DisablePersampleFragcoord" },
        { "pattern": "firefox",          "profile" : "ForceSeparateTrimThread" },
        { "pattern": "firefox",          "profile" : "FA0" },
        { "pattern": "firefox",          "profile" : "DedicatedHwStatePerCtx" },
        { "pattern": "Dirt4",               "profile" : "IdleQueueOnSwapchainOOD" },
        { "pattern": "RiseOfTheTombRaider", "profile" : "IdleQueueOnSwapchainOOD" },
        { "pattern": "ShadowOfTheTombRaider", "profile" : "IdleQueueOnSwapchainOOD" },
        { "pattern": "LifeIsStrange2", "profile" : "IdleQueueOnSwapchainOOD" },
        { "pattern": "Hitman", "profile" : "IdleQueueOnSwapchainOOD" },
        { "pattern": "F12017", "profile" : "IdleQueueOnSwapchainOOD" },
        { "pattern": "ShadowOfMordor", "profile" : "IdleQueueOnSwapchainOOD" },
        { "pattern": "MadMax", "profile" : "IdleQueueOnSwapchainOOD" },
        { "pattern": "GRIDAutosport", "profile" : "IdleQueueOnSwapchainOOD" },
        { "pattern": "DawnOfWar3",  "profile" : "DisableHostVisibleVidmem" }
    ]
}

____________________________________________

ldd /sbin/glxinfo

	linux-vdso.so.1 (0x00007ffefe3a7000)
	libGL.so.1 => /usr/lib/libGL.so.1 (0x00007f5585b66000)
	libX11.so.6 => /usr/lib/libX11.so.6 (0x00007f5585a23000)
	libc.so.6 => /usr/lib/libc.so.6 (0x00007f558583c000)
	libGLdispatch.so.0 => /usr/lib/libGLdispatch.so.0 (0x00007f5585784000)
	libGLX.so.0 => /usr/lib/libGLX.so.0 (0x00007f5585752000)
	libxcb.so.1 => /usr/lib/libxcb.so.1 (0x00007f5585727000)
	/lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007f5585c27000)
	libXau.so.6 => /usr/lib/libXau.so.6 (0x00007f5585720000)
	libXdmcp.so.6 => /usr/lib/libXdmcp.so.6 (0x00007f5585718000)

____________________________________________

Found Vulkan loader(s):
/usr/lib/libvulkan.so.1.3.226

Listing common ICD paths:
/usr/share/vulkan/icd.d/nvidia_icd.json

____________________________________________

/sbin/lspci -d "10de:*" -v -xxx

01:00.0 VGA compatible controller: NVIDIA Corporation GA106M [GeForce RTX 3060 Mobile / Max-Q] (rev a1) (prog-if 00 [VGA controller])
	Subsystem: ASUSTeK Computer Inc. Device 16a2
	Physical Slot: 0
	Flags: bus master, fast devsel, latency 0, IRQ 114, IOMMU group 14
	Memory at fb000000 (32-bit, non-prefetchable) [size=16M]
	Memory at fc00000000 (64-bit, prefetchable) [size=8G]
	Memory at fe00000000 (64-bit, prefetchable) [size=32M]
	I/O ports at f000 [size=128]
	Expansion ROM at fc000000 [virtual] [disabled] [size=512K]
	Capabilities: [60] Power Management version 3
	Capabilities: [68] MSI: Enable+ Count=1/1 Maskable- 64bit+
	Capabilities: [78] Express Legacy Endpoint, MSI 00
	Capabilities: [b4] Vendor Specific Information: Len=14 <?>
	Capabilities: [100] Virtual Channel
	Capabilities: [258] L1 PM Substates
	Capabilities: [128] Power Budgeting <?>
	Capabilities: [420] Advanced Error Reporting
	Capabilities: [600] Vendor Specific Information: ID=0001 Rev=1 Len=024 <?>
	Capabilities: [900] Secondary PCI Express
	Capabilities: [bb0] Physical Resizable BAR
	Capabilities: [c1c] Physical Layer 16.0 GT/s <?>
	Capabilities: [d00] Lane Margining at the Receiver <?>
	Capabilities: [e00] Data Link Feature <?>
	Kernel driver in use: nvidia
	Kernel modules: nouveau, nvidia_drm, nvidia
00: de 10 20 25 07 04 10 00 a1 00 00 03 00 00 80 00
10: 00 00 00 fb 0c 00 00 00 fc 00 00 00 0c 00 00 00
20: fe 00 00 00 01 f0 00 00 00 00 00 00 43 10 a2 16
30: 00 00 00 00 60 00 00 00 00 00 00 00 00 01 00 00
40: 43 10 a2 16 00 00 00 00 00 00 00 00 00 00 00 00
50: 00 00 00 00 01 00 00 00 ce d6 23 00 00 00 00 00
60: 01 68 03 48 08 00 00 00 05 78 81 00 00 00 e0 fe
70: 00 00 00 00 00 00 00 00 10 b4 12 00 e1 8d 2c 11
80: 3f 29 00 00 03 4d 45 00 00 01 83 10 00 00 00 00
90: 00 00 00 00 00 00 00 00 00 00 00 00 13 00 07 00
a0: 00 00 00 00 1e 00 80 01 03 00 1f 00 00 00 00 00
b0: 00 00 00 00 09 00 14 01 00 00 00 00 00 00 00 00
c0: 00 00 00 00 00 00 00 00 11 00 05 00 00 00 b9 00
d0: 00 00 ba 00 00 00 00 00 00 00 00 00 00 00 00 00
e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

01:00.1 Audio device: NVIDIA Corporation GA106 High Definition Audio Controller (rev a1)
	Subsystem: ASUSTeK Computer Inc. Device 16a2
	Physical Slot: 0
	Flags: bus master, fast devsel, latency 0, IRQ 112, IOMMU group 14
	Memory at fc080000 (32-bit, non-prefetchable) [size=16K]
	Capabilities: [60] Power Management version 3
	Capabilities: [68] MSI: Enable- Count=1/1 Maskable- 64bit+
	Capabilities: [78] Express Endpoint, MSI 00
	Capabilities: [100] Advanced Error Reporting
	Capabilities: [160] Data Link Feature <?>
	Kernel driver in use: snd_hda_intel
	Kernel modules: snd_hda_intel
00: de 10 8e 22 06 00 10 00 a1 00 03 04 00 00 80 00
10: 00 00 08 fc 00 00 00 00 00 00 00 00 00 00 00 00
20: 00 00 00 00 00 00 00 00 00 00 00 00 43 10 a2 16
30: 00 00 00 00 60 00 00 00 00 00 00 00 00 02 00 00
40: 43 10 a2 16 00 00 00 00 00 00 00 00 00 00 00 00
50: 00 00 00 00 00 00 00 00 ce d6 23 00 00 00 00 00
60: 01 68 03 00 0b 00 00 00 05 78 80 00 00 00 00 00
70: 00 00 00 00 00 00 00 00 10 00 02 00 e1 8d 2c 01
80: 3f 29 00 00 03 4d 45 00 00 01 83 10 00 00 00 00
90: 00 00 00 00 00 00 00 00 00 00 00 00 13 00 07 00
a0: 00 00 00 00 1e 00 80 01 00 00 01 00 00 00 00 00
b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00


____________________________________________

/sbin/lspci -d "10b5:*" -v -xxx


____________________________________________

/sbin/lspci -t

-[0000:00]-+-00.0
           +-00.2
           +-01.0
           +-01.1-[01]--+-00.0
           |            \-00.1
           +-02.0
           +-02.1-[02]----00.0
           +-02.2-[03]----00.0
           +-02.3-[04]----00.0
           +-02.4-[05]----00.0
           +-08.0
           +-08.1-[06]--+-00.0
           |            +-00.1
           |            +-00.2
           |            +-00.3
           |            +-00.4
           |            +-00.5
           |            \-00.6
           +-14.0
           +-14.3
           +-18.0
           +-18.1
           +-18.2
           +-18.3
           +-18.4
           +-18.5
           +-18.6
           \-18.7

____________________________________________

/sbin/lspci -nn

00:00.0 Host bridge [0600]: Advanced Micro Devices, Inc. [AMD] Renoir/Cezanne Root Complex [1022:1630]
00:00.2 IOMMU [0806]: Advanced Micro Devices, Inc. [AMD] Renoir/Cezanne IOMMU [1022:1631]
00:01.0 Host bridge [0600]: Advanced Micro Devices, Inc. [AMD] Renoir PCIe Dummy Host Bridge [1022:1632]
00:01.1 PCI bridge [0604]: Advanced Micro Devices, Inc. [AMD] Renoir PCIe GPP Bridge [1022:1633]
00:02.0 Host bridge [0600]: Advanced Micro Devices, Inc. [AMD] Renoir PCIe Dummy Host Bridge [1022:1632]
00:02.1 PCI bridge [0604]: Advanced Micro Devices, Inc. [AMD] Renoir/Cezanne PCIe GPP Bridge [1022:1634]
00:02.2 PCI bridge [0604]: Advanced Micro Devices, Inc. [AMD] Renoir/Cezanne PCIe GPP Bridge [1022:1634]
00:02.3 PCI bridge [0604]: Advanced Micro Devices, Inc. [AMD] Renoir/Cezanne PCIe GPP Bridge [1022:1634]
00:02.4 PCI bridge [0604]: Advanced Micro Devices, Inc. [AMD] Renoir/Cezanne PCIe GPP Bridge [1022:1634]
00:08.0 Host bridge [0600]: Advanced Micro Devices, Inc. [AMD] Renoir PCIe Dummy Host Bridge [1022:1632]
00:08.1 PCI bridge [0604]: Advanced Micro Devices, Inc. [AMD] Renoir Internal PCIe GPP Bridge to Bus [1022:1635]
00:14.0 SMBus [0c05]: Advanced Micro Devices, Inc. [AMD] FCH SMBus Controller [1022:790b] (rev 51)
00:14.3 ISA bridge [0601]: Advanced Micro Devices, Inc. [AMD] FCH LPC Bridge [1022:790e] (rev 51)
00:18.0 Host bridge [0600]: Advanced Micro Devices, Inc. [AMD] Cezanne Data Fabric; Function 0 [1022:166a]
00:18.1 Host bridge [0600]: Advanced Micro Devices, Inc. [AMD] Cezanne Data Fabric; Function 1 [1022:166b]
00:18.2 Host bridge [0600]: Advanced Micro Devices, Inc. [AMD] Cezanne Data Fabric; Function 2 [1022:166c]
00:18.3 Host bridge [0600]: Advanced Micro Devices, Inc. [AMD] Cezanne Data Fabric; Function 3 [1022:166d]
00:18.4 Host bridge [0600]: Advanced Micro Devices, Inc. [AMD] Cezanne Data Fabric; Function 4 [1022:166e]
00:18.5 Host bridge [0600]: Advanced Micro Devices, Inc. [AMD] Cezanne Data Fabric; Function 5 [1022:166f]
00:18.6 Host bridge [0600]: Advanced Micro Devices, Inc. [AMD] Cezanne Data Fabric; Function 6 [1022:1670]
00:18.7 Host bridge [0600]: Advanced Micro Devices, Inc. [AMD] Cezanne Data Fabric; Function 7 [1022:1671]
01:00.0 VGA compatible controller [0300]: NVIDIA Corporation GA106M [GeForce RTX 3060 Mobile / Max-Q] [10de:2520] (rev a1)
01:00.1 Audio device [0403]: NVIDIA Corporation GA106 High Definition Audio Controller [10de:228e] (rev a1)
02:00.0 Ethernet controller [0200]: Realtek Semiconductor Co., Ltd. RTL8111/8168/8411 PCI Express Gigabit Ethernet Controller [10ec:8168] (rev 15)
03:00.0 Network controller [0280]: Intel Corporation Wi-Fi 6 AX200 [8086:2723] (rev 1a)
04:00.0 Non-Volatile memory controller [0108]: Samsung Electronics Co Ltd NVMe SSD Controller SM981/PM981/PM983 [144d:a808]
05:00.0 Non-Volatile memory controller [0108]: Kingston Technology Company, Inc. SNVS2000G [NV1 NVMe PCIe SSD 2TB] [2646:500e] (rev 01)
06:00.0 VGA compatible controller [0300]: Advanced Micro Devices, Inc. [AMD/ATI] Cezanne [1002:1638] (rev c5)
06:00.1 Audio device [0403]: Advanced Micro Devices, Inc. [AMD/ATI] Renoir Radeon High Definition Audio Controller [1002:1637]
06:00.2 Encryption controller [1080]: Advanced Micro Devices, Inc. [AMD] Family 17h (Models 10h-1fh) Platform Security Processor [1022:15df]
06:00.3 USB controller [0c03]: Advanced Micro Devices, Inc. [AMD] Renoir/Cezanne USB 3.1 [1022:1639]
06:00.4 USB controller [0c03]: Advanced Micro Devices, Inc. [AMD] Renoir/Cezanne USB 3.1 [1022:1639]
06:00.5 Multimedia controller [0480]: Advanced Micro Devices, Inc. [AMD] ACP/ACP3X/ACP6x Audio Coprocessor [1022:15e2] (rev 01)
06:00.6 Audio device [0403]: Advanced Micro Devices, Inc. [AMD] Family 17h/19h HD Audio Controller [1022:15e3]
____________________________________________

/sbin/numactl -H

available: 1 nodes (0)
node 0 cpus: 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
node 0 size: 63708 MB
node 0 free: 54425 MB
node distances:
node   0 
  0:  10 
____________________________________________
*** /sys/devices/system/node/has_cpu
*** ls: -r--r--r-- 1 root root 4096 2022-10-27 20:48:32.417608544 -0300 /sys/devices/system/node/has_cpu
0

____________________________________________
*** /sys/devices/system/node/has_memory
*** ls: -r--r--r-- 1 root root 4096 2022-10-27 20:48:32.417608544 -0300 /sys/devices/system/node/has_memory
0

____________________________________________
*** /sys/devices/system/node/has_normal_memory
*** ls: -r--r--r-- 1 root root 4096 2022-10-27 20:48:32.417608544 -0300 /sys/devices/system/node/has_normal_memory
0

____________________________________________
*** /sys/devices/system/node/online
*** ls: -r--r--r-- 1 root root 4096 2022-10-27 20:48:32.417608544 -0300 /sys/devices/system/node/online
0

____________________________________________
*** /sys/devices/system/node/possible
*** ls: -r--r--r-- 1 root root 4096 2022-10-27 20:48:32.417608544 -0300 /sys/devices/system/node/possible
0

____________________________________________
*** /sys/bus/pci/devices/0000:01:00.0/local_cpulist
*** ls: -r--r--r-- 1 root root 4096 2022-10-27 20:48:33.960836844 -0300 /sys/bus/pci/devices/0000:01:00.0/local_cpulist
0-15

____________________________________________
*** /sys/bus/pci/devices/0000:01:00.0/numa_node
*** ls: -rw-r--r-- 1 root root 4096 2022-10-27 20:48:33.960836844 -0300 /sys/bus/pci/devices/0000:01:00.0/numa_node
-1

____________________________________________

/sbin/lsusb

Bus 004 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
Bus 003 Device 003: ID 8087:0029 Intel Corp. AX200 Bluetooth
Bus 003 Device 002: ID 046d:c534 Logitech, Inc. Unifying Receiver
Bus 003 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
Bus 002 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
Bus 001 Device 002: ID 13d3:56a2 IMC Networks USB2.0 HD UVC WebCam
Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub

____________________________________________

Skipping dmidecode output (dmidecode not found)

____________________________________________

/sbin/modinfo nvidia | grep vermagic

vermagic:       6.0.1-arch2-1 SMP preempt mod_unload 

____________________________________________

Scanning kernel log files for NVIDIA kernel messages:

  journalctl -b -0:
Oct 27 20:24:50 nomade007 kernel: nvidia-nvlink: Nvlink Core is being initialized, major device number 510
Oct 27 20:24:50 nomade007 kernel: NVRM: No NVIDIA GPU found.
Oct 27 20:24:50 nomade007 kernel: nvidia-nvlink: Unregistered Nvlink Core, major device number 510
Oct 27 20:24:54 nomade007 kernel: nvidia-nvlink: Nvlink Core is being initialized, major device number 510
Oct 27 20:24:54 nomade007 kernel: NVRM: loading NVIDIA UNIX x86_64 Kernel Module  520.56.06  Thu Oct  6 21:38:55 UTC 2022
Oct 27 20:24:54 nomade007 systemd-udevd[389]: nvidia: Process '/usr/bin/bash -c '/usr/bin/mknod -Z -m 666 /dev/nvidiactl c $(grep nvidia-frontend /proc/devices | cut -d \  -f 1) 255'' failed with exit code 1.
Oct 27 20:24:54 nomade007 systemd-udevd[398]: nvidia: Process '/usr/bin/bash -c 'for i in $(cat /proc/driver/nvidia/gpus/*/information | grep Minor | cut -d \  -f 4); do /usr/bin/mknod -Z -m 666 /dev/nvidia${i} c $(grep nvidia-frontend /proc/devices | cut -d \  -f 1) ${i}; done'' failed with exit code 1.
Oct 27 20:24:54 nomade007 systemd-udevd[389]: nvidia: Process '/usr/bin/bash -c 'for i in $(cat /proc/driver/nvidia/gpus/*/information | grep Minor | cut -d \  -f 4); do /usr/bin/mknod -Z -m 666 /dev/nvidia${i} c $(grep nvidia-frontend /proc/devices | cut -d \  -f 1) ${i}; done'' failed with exit code 1.
Oct 27 20:24:55 nomade007 kernel: nvidia-modeset: Loading NVIDIA Kernel Mode Setting Driver for UNIX platforms  520.56.06  Thu Oct  6 21:22:53 UTC 2022
Oct 27 20:24:55 nomade007 kernel: [drm] [nvidia-drm] [GPU ID 0x00000100] Loading driver
Oct 27 20:24:55 nomade007 kernel: [drm] Initialized nvidia-drm 0.0.0 20160202 for 0000:01:00.0 on minor 1
Oct 27 20:50:08 nomade007 dbus-daemon[566]: [system] Activating via systemd: service name='org.freedesktop.home1' unit='dbus-org.freedesktop.home1.service' requested by ':1.115' (uid=0 pid=6026 comm="sudo ./nvidia-bug-report.sh")
Oct 27 20:50:11 nomade007 sudo[6026]:   nomade : TTY=pts/2 ; PWD=/usr/bin ; USER=root ; COMMAND=./nvidia-bug-report.sh

  journalctl -b -1:
Oct 27 16:48:06 nomade007 kernel: nvidia-nvlink: Nvlink Core is being initialized, major device number 511
Oct 27 16:48:06 nomade007 kernel: NVRM: No NVIDIA GPU found.
Oct 27 16:48:06 nomade007 kernel: nvidia-nvlink: Unregistered Nvlink Core, major device number 511
Oct 27 16:48:09 nomade007 kernel: nvidia-nvlink: Nvlink Core is being initialized, major device number 511
Oct 27 16:48:09 nomade007 kernel: NVRM: loading NVIDIA UNIX x86_64 Kernel Module  520.56.06  Thu Oct  6 21:38:55 UTC 2022
Oct 27 16:48:09 nomade007 systemd-udevd[409]: nvidia: Process '/usr/bin/bash -c '/usr/bin/mknod -Z -m 666 /dev/nvidiactl c $(grep nvidia-frontend /proc/devices | cut -d \  -f 1) 255'' failed with exit code 1.
Oct 27 16:48:09 nomade007 systemd-udevd[359]: nvidia: Process '/usr/bin/bash -c 'for i in $(cat /proc/driver/nvidia/gpus/*/information | grep Minor | cut -d \  -f 4); do /usr/bin/mknod -Z -m 666 /dev/nvidia${i} c $(grep nvidia-frontend /proc/devices | cut -d \  -f 1) ${i}; done'' failed with exit code 1.
Oct 27 16:48:09 nomade007 kernel: nvidia-modeset: Loading NVIDIA Kernel Mode Setting Driver for UNIX platforms  520.56.06  Thu Oct  6 21:22:53 UTC 2022
Oct 27 16:48:09 nomade007 kernel: [drm] [nvidia-drm] [GPU ID 0x00000100] Loading driver
Oct 27 16:48:09 nomade007 kernel: [drm] Initialized nvidia-drm 0.0.0 20160202 for 0000:01:00.0 on minor 1

  journalctl -b -2:
Oct 27 13:33:59 nomade007 kernel: nvidia-nvlink: Nvlink Core is being initialized, major device number 511
Oct 27 13:33:59 nomade007 kernel: NVRM: No NVIDIA GPU found.
Oct 27 13:33:59 nomade007 kernel: nvidia-nvlink: Unregistered Nvlink Core, major device number 511
Oct 27 13:34:02 nomade007 kernel: nvidia-nvlink: Nvlink Core is being initialized, major device number 511
Oct 27 13:34:02 nomade007 kernel: NVRM: loading NVIDIA UNIX x86_64 Kernel Module  520.56.06  Thu Oct  6 21:38:55 UTC 2022
Oct 27 13:34:02 nomade007 systemd-udevd[397]: nvidia: Process '/usr/bin/bash -c '/usr/bin/mknod -Z -m 666 /dev/nvidiactl c $(grep nvidia-frontend /proc/devices | cut -d \  -f 1) 255'' failed with exit code 1.
Oct 27 13:34:02 nomade007 systemd-udevd[363]: nvidia: Process '/usr/bin/bash -c 'for i in $(cat /proc/driver/nvidia/gpus/*/information | grep Minor | cut -d \  -f 4); do /usr/bin/mknod -Z -m 666 /dev/nvidia${i} c $(grep nvidia-frontend /proc/devices | cut -d \  -f 1) ${i}; done'' failed with exit code 1.
Oct 27 13:34:02 nomade007 systemd-udevd[397]: nvidia: Process '/usr/bin/bash -c 'for i in $(cat /proc/driver/nvidia/gpus/*/information | grep Minor | cut -d \  -f 4); do /usr/bin/mknod -Z -m 666 /dev/nvidia${i} c $(grep nvidia-frontend /proc/devices | cut -d \  -f 1) ${i}; done'' failed with exit code 1.
Oct 27 13:34:03 nomade007 kernel: nvidia-modeset: Loading NVIDIA Kernel Mode Setting Driver for UNIX platforms  520.56.06  Thu Oct  6 21:22:53 UTC 2022
Oct 27 13:34:03 nomade007 kernel: [drm] [nvidia-drm] [GPU ID 0x00000100] Loading driver
Oct 27 13:34:03 nomade007 kernel: [drm] Initialized nvidia-drm 0.0.0 20160202 for 0000:01:00.0 on minor 1

____________________________________________

dmesg:

[    0.000000] Linux version 6.0.1-arch2-1 (linux@archlinux) (gcc (GCC) 12.2.0, GNU ld (GNU Binutils) 2.39.0) #1 SMP PREEMPT_DYNAMIC Thu, 13 Oct 2022 18:58:49 +0000
[    0.000000] Command line: initrd=\amd-ucode.img initrd=\initramfs-linux.img root=PARTUUID=f407dfcd-5b75-c540-99c7-811fac3135b7 rw
[    0.000000] x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'
[    0.000000] x86/fpu: Supporting XSAVE feature 0x002: 'SSE registers'
[    0.000000] x86/fpu: Supporting XSAVE feature 0x004: 'AVX registers'
[    0.000000] x86/fpu: Supporting XSAVE feature 0x200: 'Protection Keys User registers'
[    0.000000] x86/fpu: xstate_offset[2]:  576, xstate_sizes[2]:  256
[    0.000000] x86/fpu: xstate_offset[9]:  832, xstate_sizes[9]:    8
[    0.000000] x86/fpu: Enabled xstate features 0x207, context size is 840 bytes, using 'compacted' format.
[    0.000000] signal: max sigframe size: 3376
[    0.000000] BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009ffff] usable
[    0.000000] BIOS-e820: [mem 0x00000000000a0000-0x00000000000fffff] reserved
[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x0000000009bfefff] usable
[    0.000000] BIOS-e820: [mem 0x0000000009bff000-0x000000000a000fff] reserved
[    0.000000] BIOS-e820: [mem 0x000000000a001000-0x000000000a1fffff] usable
[    0.000000] BIOS-e820: [mem 0x000000000a200000-0x000000000a20efff] ACPI NVS
[    0.000000] BIOS-e820: [mem 0x000000000a20f000-0x00000000eaed3fff] usable
[    0.000000] BIOS-e820: [mem 0x00000000eaed4000-0x00000000ec3eefff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000ec3ef000-0x00000000ec44efff] ACPI data
[    0.000000] BIOS-e820: [mem 0x00000000ec44f000-0x00000000ec782fff] ACPI NVS
[    0.000000] BIOS-e820: [mem 0x00000000ec783000-0x00000000ecffefff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000ecfff000-0x00000000edffffff] usable
[    0.000000] BIOS-e820: [mem 0x00000000ee000000-0x00000000f7ffffff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000fd000000-0x00000000fdffffff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000feb80000-0x00000000fec01fff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000fec10000-0x00000000fec10fff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000fed00000-0x00000000fed00fff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000fed40000-0x00000000fed44fff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000fed80000-0x00000000fed8ffff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000fedc4000-0x00000000fedc9fff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000fedcc000-0x00000000fedcefff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000fedd5000-0x00000000fedd5fff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000ff000000-0x00000000ffffffff] reserved
[    0.000000] BIOS-e820: [mem 0x0000000100000000-0x0000000fee2fffff] usable
[    0.000000] BIOS-e820: [mem 0x0000000fee300000-0x000000100fffffff] reserved
[    0.000000] NX (Execute Disable) protection: active
[    0.000000] e820: update [mem 0xdf1ba018-0xdf1c9e57] usable ==> usable
[    0.000000] e820: update [mem 0xdf1ba018-0xdf1c9e57] usable ==> usable
[    0.000000] e820: update [mem 0xdf1ac018-0xdf1b9857] usable ==> usable
[    0.000000] e820: update [mem 0xdf1ac018-0xdf1b9857] usable ==> usable
[    0.000000] extended physical RAM map:
[    0.000000] reserve setup_data: [mem 0x0000000000000000-0x000000000009ffff] usable
[    0.000000] reserve setup_data: [mem 0x00000000000a0000-0x00000000000fffff] reserved
[    0.000000] reserve setup_data: [mem 0x0000000000100000-0x0000000009bfefff] usable
[    0.000000] reserve setup_data: [mem 0x0000000009bff000-0x000000000a000fff] reserved
[    0.000000] reserve setup_data: [mem 0x000000000a001000-0x000000000a1fffff] usable
[    0.000000] reserve setup_data: [mem 0x000000000a200000-0x000000000a20efff] ACPI NVS
[    0.000000] reserve setup_data: [mem 0x000000000a20f000-0x00000000df1ac017] usable
[    0.000000] reserve setup_data: [mem 0x00000000df1ac018-0x00000000df1b9857] usable
[    0.000000] reserve setup_data: [mem 0x00000000df1b9858-0x00000000df1ba017] usable
[    0.000000] reserve setup_data: [mem 0x00000000df1ba018-0x00000000df1c9e57] usable
[    0.000000] reserve setup_data: [mem 0x00000000df1c9e58-0x00000000eaed3fff] usable
[    0.000000] reserve setup_data: [mem 0x00000000eaed4000-0x00000000ec3eefff] reserved
[    0.000000] reserve setup_data: [mem 0x00000000ec3ef000-0x00000000ec44efff] ACPI data
[    0.000000] reserve setup_data: [mem 0x00000000ec44f000-0x00000000ec782fff] ACPI NVS
[    0.000000] reserve setup_data: [mem 0x00000000ec783000-0x00000000ecffefff] reserved
[    0.000000] reserve setup_data: [mem 0x00000000ecfff000-0x00000000edffffff] usable
[    0.000000] reserve setup_data: [mem 0x00000000ee000000-0x00000000f7ffffff] reserved
[    0.000000] reserve setup_data: [mem 0x00000000fd000000-0x00000000fdffffff] reserved
[    0.000000] reserve setup_data: [mem 0x00000000feb80000-0x00000000fec01fff] reserved
[    0.000000] reserve setup_data: [mem 0x00000000fec10000-0x00000000fec10fff] reserved
[    0.000000] reserve setup_data: [mem 0x00000000fed00000-0x00000000fed00fff] reserved
[    0.000000] reserve setup_data: [mem 0x00000000fed40000-0x00000000fed44fff] reserved
[    0.000000] reserve setup_data: [mem 0x00000000fed80000-0x00000000fed8ffff] reserved
[    0.000000] reserve setup_data: [mem 0x00000000fedc4000-0x00000000fedc9fff] reserved
[    0.000000] reserve setup_data: [mem 0x00000000fedcc000-0x00000000fedcefff] reserved
[    0.000000] reserve setup_data: [mem 0x00000000fedd5000-0x00000000fedd5fff] reserved
[    0.000000] reserve setup_data: [mem 0x00000000ff000000-0x00000000ffffffff] reserved
[    0.000000] reserve setup_data: [mem 0x0000000100000000-0x0000000fee2fffff] usable
[    0.000000] reserve setup_data: [mem 0x0000000fee300000-0x000000100fffffff] reserved
[    0.000000] efi: EFI v2.70 by American Megatrends
[    0.000000] efi: ACPI=0xec44e000 ACPI 2.0=0xec44e014 TPMFinalLog=0xec73a000 SMBIOS=0xece15000 SMBIOS 3.0=0xece14000 MEMATTR=0xdf1f1018 ESRT=0xe9a46c98 RNG=0xece52f18 TPMEventLog=0xdf1ca018 
[    0.000000] efi: seeding entropy pool
[    0.000000] random: crng init done
[    0.000000] SMBIOS 3.3.0 present.
[    0.000000] DMI: ASUSTeK COMPUTER INC. ASUS TUF Gaming A15 FA506QM_FA506QM/FA506QM, BIOS FA506QM.311 06/06/2022
[    0.000000] tsc: Fast TSC calibration using PIT
[    0.000000] tsc: Detected 3193.838 MHz processor
[    0.000127] e820: update [mem 0x00000000-0x00000fff] usable ==> reserved
[    0.000129] e820: remove [mem 0x000a0000-0x000fffff] usable
[    0.000134] last_pfn = 0xfee300 max_arch_pfn = 0x400000000
[    0.000513] x86/PAT: Configuration [0-7]: WB  WC  UC- UC  WB  WP  UC- WT  
[    0.000690] e820: update [mem 0xf0000000-0xffffffff] usable ==> reserved
[    0.000695] last_pfn = 0xee000 max_arch_pfn = 0x400000000
[    0.003420] esrt: Reserving ESRT space from 0x00000000e9a46c98 to 0x00000000e9a46cd0.
[    0.003426] e820: update [mem 0xe9a46000-0xe9a46fff] usable ==> reserved
[    0.003458] Using GB pages for direct mapping
[    0.003786] Secure boot disabled
[    0.003786] RAMDISK: [mem 0x7f74a000-0x7fff2fff]
[    0.003789] ACPI: Early table checksum verification disabled
[    0.003792] ACPI: RSDP 0x00000000EC44E014 000024 (v02 _ASUS_)
[    0.003794] ACPI: XSDT 0x00000000EC44D728 000104 (v01 _ASUS_ Notebook 01072009 AMI  01000013)
[    0.003797] ACPI: FACP 0x00000000EC43E000 000114 (v06 _ASUS_ Notebook 01072009 AMI  00010013)
[    0.003801] ACPI: DSDT 0x00000000EC433000 00A18F (v02 _ASUS_ Notebook 01072009 INTL 20190509)
[    0.003803] ACPI: FACS 0x00000000EC738000 000040
[    0.003804] ACPI: MSDM 0x00000000EC44C000 000055 (v03 _ASUS_ Notebook 01072009 ASUS 00000001)
[    0.003806] ACPI: SSDT 0x00000000EC444000 00729D (v02 AMD    AmdTable 00000002 MSFT 02000002)
[    0.003808] ACPI: IVRS 0x00000000EC443000 0001A4 (v02 AMD    AmdTable 00000001 AMD  00000000)
[    0.003809] ACPI: SSDT 0x00000000EC43F000 003A21 (v01 AMD    AMD AOD  00000001 INTL 20190509)
[    0.003811] ACPI: FIDT 0x00000000EC432000 00009C (v01 _ASUS_ Notebook 01072009 AMI  00010013)
[    0.003812] ACPI: MCFG 0x00000000EC431000 00003C (v01 _ASUS_ Notebook 01072009 MSFT 00010013)
[    0.003814] ACPI: HPET 0x00000000EC430000 000038 (v01 _ASUS_ Notebook 01072009 AMI  00000005)
[    0.003815] ACPI: VFCT 0x00000000EC422000 00D884 (v01 _ASUS_ Notebook 00000001 AMD  31504F47)
[    0.003817] ACPI: TPM2 0x00000000EC420000 00004C (v04 _ASUS_ Notebook 00000001 AMI  00000000)
[    0.003818] ACPI: SSDT 0x00000000EC41A000 005354 (v02 AMD    AmdTable 00000001 AMD  00000001)
[    0.003820] ACPI: CRAT 0x00000000EC419000 000EE8 (v01 AMD    AmdTable 00000001 AMD  00000001)
[    0.003821] ACPI: CDIT 0x00000000EC418000 000029 (v01 AMD    AmdTable 00000001 AMD  00000001)
[    0.003823] ACPI: BGRT 0x00000000EC421000 000038 (v01 _ASUS_ Notebook 01072009 AMI  00010013)
[    0.003824] ACPI: SSDT 0x00000000EC414000 003006 (v01 OptRf2 Opt2Tabl 00001000 INTL 20190509)
[    0.003826] ACPI: SSDT 0x00000000EC413000 000149 (v01 AMD    AmdTable 00000001 INTL 20190509)
[    0.003827] ACPI: SSDT 0x00000000EC411000 001486 (v01 AMD    AmdTable 00000001 INTL 20190509)
[    0.003829] ACPI: SSDT 0x00000000EC40F000 0014F6 (v01 AMD    AmdTable 00000001 INTL 20190509)
[    0.003830] ACPI: SSDT 0x00000000EC40B000 0036E3 (v01 AMD    AmdTable 00000001 INTL 20190509)
[    0.003832] ACPI: WSMT 0x00000000EC40A000 000028 (v01 _ASUS_ Notebook 01072009 AMI  00010013)
[    0.003833] ACPI: APIC 0x00000000EC409000 0000DE (v03 _ASUS_ Notebook 01072009 AMI  00010013)
[    0.003835] ACPI: SSDT 0x00000000EC408000 00008D (v01 AMD    AmdTable 00000001 INTL 20190509)
[    0.003836] ACPI: SSDT 0x00000000EC407000 00089C (v01 AMD    AmdTable 00000001 INTL 20190509)
[    0.003837] ACPI: SSDT 0x00000000EC406000 000ABB (v01 AMD    AmdTable 00000001 INTL 20190509)
[    0.003839] ACPI: SSDT 0x00000000EC405000 000241 (v01 AMD    AmdTable 00000001 INTL 20190509)
[    0.003840] ACPI: SSDT 0x00000000EC404000 000684 (v01 AMD    AmdTable 00000001 INTL 20190509)
[    0.003842] ACPI: SSDT 0x00000000EC403000 00093A (v01 AMD    AmdTable 00000001 INTL 20190509)
[    0.003843] ACPI: FPDT 0x00000000EC402000 000044 (v01 _ASUS_ A M I    01072009 AMI  01000013)
[    0.003845] ACPI: Reserving FACP table memory at [mem 0xec43e000-0xec43e113]
[    0.003845] ACPI: Reserving DSDT table memory at [mem 0xec433000-0xec43d18e]
[    0.003846] ACPI: Reserving FACS table memory at [mem 0xec738000-0xec73803f]
[    0.003847] ACPI: Reserving MSDM table memory at [mem 0xec44c000-0xec44c054]
[    0.003847] ACPI: Reserving SSDT table memory at [mem 0xec444000-0xec44b29c]
[    0.003848] ACPI: Reserving IVRS table memory at [mem 0xec443000-0xec4431a3]
[    0.003849] ACPI: Reserving SSDT table memory at [mem 0xec43f000-0xec442a20]
[    0.003849] ACPI: Reserving FIDT table memory at [mem 0xec432000-0xec43209b]
[    0.003850] ACPI: Reserving MCFG table memory at [mem 0xec431000-0xec43103b]
[    0.003850] ACPI: Reserving HPET table memory at [mem 0xec430000-0xec430037]
[    0.003851] ACPI: Reserving VFCT table memory at [mem 0xec422000-0xec42f883]
[    0.003852] ACPI: Reserving TPM2 table memory at [mem 0xec420000-0xec42004b]
[    0.003852] ACPI: Reserving SSDT table memory at [mem 0xec41a000-0xec41f353]
[    0.003853] ACPI: Reserving CRAT table memory at [mem 0xec419000-0xec419ee7]
[    0.003854] ACPI: Reserving CDIT table memory at [mem 0xec418000-0xec418028]
[    0.003854] ACPI: Reserving BGRT table memory at [mem 0xec421000-0xec421037]
[    0.003855] ACPI: Reserving SSDT table memory at [mem 0xec414000-0xec417005]
[    0.003855] ACPI: Reserving SSDT table memory at [mem 0xec413000-0xec413148]
[    0.003856] ACPI: Reserving SSDT table memory at [mem 0xec411000-0xec412485]
[    0.003857] ACPI: Reserving SSDT table memory at [mem 0xec40f000-0xec4104f5]
[    0.003857] ACPI: Reserving SSDT table memory at [mem 0xec40b000-0xec40e6e2]
[    0.003858] ACPI: Reserving WSMT table memory at [mem 0xec40a000-0xec40a027]
[    0.003859] ACPI: Reserving APIC table memory at [mem 0xec409000-0xec4090dd]
[    0.003859] ACPI: Reserving SSDT table memory at [mem 0xec408000-0xec40808c]
[    0.003860] ACPI: Reserving SSDT table memory at [mem 0xec407000-0xec40789b]
[    0.003861] ACPI: Reserving SSDT table memory at [mem 0xec406000-0xec406aba]
[    0.003861] ACPI: Reserving SSDT table memory at [mem 0xec405000-0xec405240]
[    0.003862] ACPI: Reserving SSDT table memory at [mem 0xec404000-0xec404683]
[    0.003863] ACPI: Reserving SSDT table memory at [mem 0xec403000-0xec403939]
[    0.003863] ACPI: Reserving FPDT table memory at [mem 0xec402000-0xec402043]
[    0.003915] No NUMA configuration found
[    0.003916] Faking a node at [mem 0x0000000000000000-0x0000000fee2fffff]
[    0.003918] NODE_DATA(0) allocated [mem 0xfee2fc000-0xfee2fffff]
[    0.003965] Zone ranges:
[    0.003966]   DMA      [mem 0x0000000000001000-0x0000000000ffffff]
[    0.003967]   DMA32    [mem 0x0000000001000000-0x00000000ffffffff]
[    0.003968]   Normal   [mem 0x0000000100000000-0x0000000fee2fffff]
[    0.003968]   Device   empty
[    0.003969] Movable zone start for each node
[    0.003969] Early memory node ranges
[    0.003970]   node   0: [mem 0x0000000000001000-0x000000000009ffff]
[    0.003970]   node   0: [mem 0x0000000000100000-0x0000000009bfefff]
[    0.003971]   node   0: [mem 0x000000000a001000-0x000000000a1fffff]
[    0.003971]   node   0: [mem 0x000000000a20f000-0x00000000eaed3fff]
[    0.003972]   node   0: [mem 0x00000000ecfff000-0x00000000edffffff]
[    0.003972]   node   0: [mem 0x0000000100000000-0x0000000fee2fffff]
[    0.003976] Initmem setup node 0 [mem 0x0000000000001000-0x0000000fee2fffff]
[    0.003978] On node 0, zone DMA: 1 pages in unavailable ranges
[    0.003989] On node 0, zone DMA: 96 pages in unavailable ranges
[    0.004078] On node 0, zone DMA32: 1026 pages in unavailable ranges
[    0.007573] On node 0, zone DMA32: 15 pages in unavailable ranges
[    0.007639] On node 0, zone DMA32: 8491 pages in unavailable ranges
[    0.072258] On node 0, zone Normal: 8192 pages in unavailable ranges
[    0.072300] On node 0, zone Normal: 7424 pages in unavailable ranges
[    0.072669] ACPI: PM-Timer IO Port: 0x808
[    0.072675] ACPI: LAPIC_NMI (acpi_id[0xff] high edge lint[0x1])
[    0.072687] IOAPIC[0]: apic_id 33, version 33, address 0xfec00000, GSI 0-23
[    0.072692] IOAPIC[1]: apic_id 34, version 33, address 0xfec01000, GSI 24-55
[    0.072693] ACPI: INT_SRC_OVR (bus 0 bus_irq 0 global_irq 2 dfl dfl)
[    0.072694] ACPI: INT_SRC_OVR (bus 0 bus_irq 9 global_irq 9 low level)
[    0.072697] ACPI: Using ACPI (MADT) for SMP configuration information
[    0.072697] ACPI: HPET id: 0x10228201 base: 0xfed00000
[    0.072707] e820: update [mem 0xe7d72000-0xe7da0fff] usable ==> reserved
[    0.072717] smpboot: Allowing 16 CPUs, 0 hotplug CPUs
[    0.072741] PM: hibernation: Registered nosave memory: [mem 0x00000000-0x00000fff]
[    0.072742] PM: hibernation: Registered nosave memory: [mem 0x000a0000-0x000fffff]
[    0.072743] PM: hibernation: Registered nosave memory: [mem 0x09bff000-0x0a000fff]
[    0.072745] PM: hibernation: Registered nosave memory: [mem 0x0a200000-0x0a20efff]
[    0.072746] PM: hibernation: Registered nosave memory: [mem 0xdf1ac000-0xdf1acfff]
[    0.072747] PM: hibernation: Registered nosave memory: [mem 0xdf1b9000-0xdf1b9fff]
[    0.072747] PM: hibernation: Registered nosave memory: [mem 0xdf1ba000-0xdf1bafff]
[    0.072748] PM: hibernation: Registered nosave memory: [mem 0xdf1c9000-0xdf1c9fff]
[    0.072749] PM: hibernation: Registered nosave memory: [mem 0xe7d72000-0xe7da0fff]
[    0.072751] PM: hibernation: Registered nosave memory: [mem 0xe9a46000-0xe9a46fff]
[    0.072752] PM: hibernation: Registered nosave memory: [mem 0xeaed4000-0xec3eefff]
[    0.072752] PM: hibernation: Registered nosave memory: [mem 0xec3ef000-0xec44efff]
[    0.072752] PM: hibernation: Registered nosave memory: [mem 0xec44f000-0xec782fff]
[    0.072753] PM: hibernation: Registered nosave memory: [mem 0xec783000-0xecffefff]
[    0.072754] PM: hibernation: Registered nosave memory: [mem 0xee000000-0xf7ffffff]
[    0.072754] PM: hibernation: Registered nosave memory: [mem 0xf8000000-0xfcffffff]
[    0.072754] PM: hibernation: Registered nosave memory: [mem 0xfd000000-0xfdffffff]
[    0.072755] PM: hibernation: Registered nosave memory: [mem 0xfe000000-0xfeb7ffff]
[    0.072755] PM: hibernation: Registered nosave memory: [mem 0xfeb80000-0xfec01fff]
[    0.072755] PM: hibernation: Registered nosave memory: [mem 0xfec02000-0xfec0ffff]
[    0.072756] PM: hibernation: Registered nosave memory: [mem 0xfec10000-0xfec10fff]
[    0.072756] PM: hibernation: Registered nosave memory: [mem 0xfec11000-0xfecfffff]
[    0.072756] PM: hibernation: Registered nosave memory: [mem 0xfed00000-0xfed00fff]
[    0.072757] PM: hibernation: Registered nosave memory: [mem 0xfed01000-0xfed3ffff]
[    0.072757] PM: hibernation: Registered nosave memory: [mem 0xfed40000-0xfed44fff]
[    0.072757] PM: hibernation: Registered nosave memory: [mem 0xfed45000-0xfed7ffff]
[    0.072758] PM: hibernation: Registered nosave memory: [mem 0xfed80000-0xfed8ffff]
[    0.072758] PM: hibernation: Registered nosave memory: [mem 0xfed90000-0xfedc3fff]
[    0.072758] PM: hibernation: Registered nosave memory: [mem 0xfedc4000-0xfedc9fff]
[    0.072759] PM: hibernation: Registered nosave memory: [mem 0xfedca000-0xfedcbfff]
[    0.072759] PM: hibernation: Registered nosave memory: [mem 0xfedcc000-0xfedcefff]
[    0.072759] PM: hibernation: Registered nosave memory: [mem 0xfedcf000-0xfedd4fff]
[    0.072759] PM: hibernation: Registered nosave memory: [mem 0xfedd5000-0xfedd5fff]
[    0.072760] PM: hibernation: Registered nosave memory: [mem 0xfedd6000-0xfeffffff]
[    0.072760] PM: hibernation: Registered nosave memory: [mem 0xff000000-0xffffffff]
[    0.072761] [mem 0xf8000000-0xfcffffff] available for PCI devices
[    0.072762] Booting paravirtualized kernel on bare hardware
[    0.072764] clocksource: refined-jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 6370452778343963 ns
[    0.075468] setup_percpu: NR_CPUS:320 nr_cpumask_bits:320 nr_cpu_ids:16 nr_node_ids:1
[    0.075827] percpu: Embedded 63 pages/cpu s221184 r8192 d28672 u262144
[    0.075832] pcpu-alloc: s221184 r8192 d28672 u262144 alloc=1*2097152
[    0.075833] pcpu-alloc: [0] 00 01 02 03 04 05 06 07 [0] 08 09 10 11 12 13 14 15 
[    0.075852] Fallback order for Node 0: 0 
[    0.075855] Built 1 zonelists, mobility grouping on.  Total pages: 16361036
[    0.075855] Policy zone: Normal
[    0.075856] Kernel command line: initrd=\amd-ucode.img initrd=\initramfs-linux.img root=PARTUUID=f407dfcd-5b75-c540-99c7-811fac3135b7 rw
[    0.079947] Dentry cache hash table entries: 8388608 (order: 14, 67108864 bytes, linear)
[    0.081955] Inode-cache hash table entries: 4194304 (order: 13, 33554432 bytes, linear)
[    0.082117] mem auto-init: stack:all(zero), heap alloc:on, heap free:off
[    0.082157] software IO TLB: area num 16.
[    0.161129] Memory: 65122912K/66483596K available (14343K kernel code, 2078K rwdata, 11320K rodata, 2120K init, 3548K bss, 1360424K reserved, 0K cma-reserved)
[    0.161202] SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=16, Nodes=1
[    0.161209] ftrace: allocating 45769 entries in 179 pages
[    0.168543] ftrace: allocated 179 pages with 5 groups
[    0.168592] Dynamic Preempt: full
[    0.168616] rcu: Preemptible hierarchical RCU implementation.
[    0.168616] rcu: 	RCU restricting CPUs from NR_CPUS=320 to nr_cpu_ids=16.
[    0.168617] rcu: 	RCU priority boosting: priority 1 delay 500 ms.
[    0.168618] 	Trampoline variant of Tasks RCU enabled.
[    0.168618] 	Rude variant of Tasks RCU enabled.
[    0.168618] 	Tracing variant of Tasks RCU enabled.
[    0.168619] rcu: RCU calculated value of scheduler-enlistment delay is 30 jiffies.
[    0.168619] rcu: Adjusting geometry for rcu_fanout_leaf=16, nr_cpu_ids=16
[    0.170949] NR_IRQS: 20736, nr_irqs: 1096, preallocated irqs: 16
[    0.171115] rcu: srcu_init: Setting srcu_struct sizes based on contention.
[    0.171185] kfence: initialized - using 2097152 bytes for 255 objects at 0x00000000c07f0bcf-0x0000000073122325
[    0.171218] Console: colour dummy device 80x25
[    0.171230] printk: console [tty0] enabled
[    0.171242] ACPI: Core revision 20220331
[    0.171371] clocksource: hpet: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 133484873504 ns
[    0.171387] APIC: Switch to symmetric I/O mode setup
[    0.172126] AMD-Vi: ivrs, add hid:AMDI0020, uid:\_SB.FUR0, rdevid:160
[    0.172127] AMD-Vi: ivrs, add hid:AMDI0020, uid:\_SB.FUR1, rdevid:160
[    0.172128] AMD-Vi: ivrs, add hid:AMDI0020, uid:\_SB.FUR2, rdevid:160
[    0.172128] AMD-Vi: ivrs, add hid:AMDI0020, uid:\_SB.FUR3, rdevid:160
[    0.172129] AMD-Vi: Using global IVHD EFR:0x206d73ef22254ade, EFR2:0x0
[    0.172367] Switched APIC routing to physical flat.
[    0.172966] ..TIMER: vector=0x30 apic1=0 pin1=2 apic2=-1 pin2=-1
[    0.188061] clocksource: tsc-early: mask: 0xffffffffffffffff max_cycles: 0x2e098d31503, max_idle_ns: 440795278573 ns
[    0.188066] Calibrating delay loop (skipped), value calculated using timer frequency.. 6390.82 BogoMIPS (lpj=10646126)
[    0.188068] pid_max: default: 32768 minimum: 301
[    0.190537] LSM: Security Framework initializing
[    0.190543] landlock: Up and running.
[    0.190543] Yama: becoming mindful.
[    0.190548] LSM support for eBPF active
[    0.190673] Mount-cache hash table entries: 131072 (order: 8, 1048576 bytes, linear)
[    0.190796] Mountpoint-cache hash table entries: 131072 (order: 8, 1048576 bytes, linear)
[    0.190973] x86/cpu: User Mode Instruction Prevention (UMIP) activated
[    0.190982] LVT offset 1 assigned for vector 0xf9
[    0.190995] LVT offset 2 assigned for vector 0xf4
[    0.190998] process: using mwait in idle threads
[    0.190999] Last level iTLB entries: 4KB 512, 2MB 512, 4MB 256
[    0.191000] Last level dTLB entries: 4KB 2048, 2MB 2048, 4MB 1024, 1GB 0
[    0.191003] Spectre V1 : Mitigation: usercopy/swapgs barriers and __user pointer sanitization
[    0.191005] Spectre V2 : Mitigation: Retpolines
[    0.191005] Spectre V2 : Spectre v2 / SpectreRSB mitigation: Filling RSB on context switch
[    0.191006] Spectre V2 : Spectre v2 / SpectreRSB : Filling RSB on VMEXIT
[    0.191006] Spectre V2 : Enabling Restricted Speculation for firmware calls
[    0.191007] Spectre V2 : mitigation: Enabling conditional Indirect Branch Prediction Barrier
[    0.191008] Spectre V2 : User space: Mitigation: STIBP always-on protection
[    0.191009] Speculative Store Bypass: Mitigation: Speculative Store Bypass disabled via prctl
[    0.204682] Freeing SMP alternatives memory: 36K
[    0.312076] smpboot: CPU0: AMD Ryzen 7 5800H with Radeon Graphics (family: 0x19, model: 0x50, stepping: 0x0)
[    0.312188] cblist_init_generic: Setting adjustable number of callback queues.
[    0.312191] cblist_init_generic: Setting shift to 4 and lim to 1.
[    0.312204] cblist_init_generic: Setting shift to 4 and lim to 1.
[    0.312212] cblist_init_generic: Setting shift to 4 and lim to 1.
[    0.312218] Performance Events: Fam17h+ core perfctr, AMD PMU driver.
[    0.312222] ... version:                0
[    0.312222] ... bit width:              48
[    0.312223] ... generic registers:      6
[    0.312223] ... value mask:             0000ffffffffffff
[    0.312224] ... max period:             00007fffffffffff
[    0.312224] ... fixed-purpose events:   0
[    0.312224] ... event mask:             000000000000003f
[    0.312276] rcu: Hierarchical SRCU implementation.
[    0.312276] rcu: 	Max phase no-delay instances is 1000.
[    0.312581] NMI watchdog: Enabled. Permanently consumes one hw-PMU counter.
[    0.312687] smp: Bringing up secondary CPUs ...
[    0.312753] x86: Booting SMP configuration:
[    0.312754] .... node  #0, CPUs:        #1
[    0.314823] Spectre V2 : Update user space SMT mitigation: STIBP always-on
[    0.314855]   #2  #3  #4  #5  #6  #7  #8  #9 #10 #11 #12 #13 #14 #15
[    0.344750] smp: Brought up 1 node, 16 CPUs
[    0.344750] smpboot: Max logical packages: 1
[    0.344750] smpboot: Total of 16 processors activated (102243.26 BogoMIPS)
[    0.346186] devtmpfs: initialized
[    0.346186] x86/mm: Memory block size: 128MB
[    0.349320] ACPI: PM: Registering ACPI NVS region [mem 0x0a200000-0x0a20efff] (61440 bytes)
[    0.349320] ACPI: PM: Registering ACPI NVS region [mem 0xec44f000-0xec782fff] (3358720 bytes)
[    0.349320] clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 6370867519511994 ns
[    0.349320] futex hash table entries: 4096 (order: 6, 262144 bytes, linear)
[    0.349320] pinctrl core: initialized pinctrl subsystem
[    0.349320] PM: RTC time: 23:24:48, date: 2022-10-27
[    0.349320] NET: Registered PF_NETLINK/PF_ROUTE protocol family
[    0.349320] DMA: preallocated 4096 KiB GFP_KERNEL pool for atomic allocations
[    0.349320] DMA: preallocated 4096 KiB GFP_KERNEL|GFP_DMA pool for atomic allocations
[    0.349320] DMA: preallocated 4096 KiB GFP_KERNEL|GFP_DMA32 pool for atomic allocations
[    0.349320] audit: initializing netlink subsys (disabled)
[    0.349320] audit: type=2000 audit(1666913088.176:1): state=initialized audit_enabled=0 res=1
[    0.349320] thermal_sys: Registered thermal governor 'fair_share'
[    0.349320] thermal_sys: Registered thermal governor 'bang_bang'
[    0.349320] thermal_sys: Registered thermal governor 'step_wise'
[    0.349320] thermal_sys: Registered thermal governor 'user_space'
[    0.349320] thermal_sys: Registered thermal governor 'power_allocator'
[    0.349320] cpuidle: using governor ladder
[    0.349320] cpuidle: using governor menu
[    0.349320] acpiphp: ACPI Hot Plug PCI Controller Driver version: 0.5
[    0.349320] PCI: MMCONFIG for domain 0000 [bus 00-7f] at [mem 0xf0000000-0xf7ffffff] (base 0xf0000000)
[    0.349320] PCI: MMCONFIG at [mem 0xf0000000-0xf7ffffff] reserved in E820
[    0.349320] PCI: Using configuration type 1 for base access
[    0.351532] kprobes: kprobe jump-optimization is enabled. All kprobes are optimized if possible.
[    0.351587] HugeTLB: registered 1.00 GiB page size, pre-allocated 0 pages
[    0.351587] HugeTLB: 16380 KiB vmemmap can be freed for a 1.00 GiB page
[    0.351587] HugeTLB: registered 2.00 MiB page size, pre-allocated 0 pages
[    0.351587] HugeTLB: 28 KiB vmemmap can be freed for a 2.00 MiB page
[    0.351587] ACPI: Added _OSI(Module Device)
[    0.351587] ACPI: Added _OSI(Processor Device)
[    0.351587] ACPI: Added _OSI(3.0 _SCP Extensions)
[    0.351587] ACPI: Added _OSI(Processor Aggregator Device)
[    0.351587] ACPI: Added _OSI(Linux-Dell-Video)
[    0.351587] ACPI: Added _OSI(Linux-Lenovo-NV-HDMI-Audio)
[    0.351587] ACPI: Added _OSI(Linux-HPI-Hybrid-Graphics)
[    0.359825] ACPI: 15 ACPI AML tables successfully acquired and loaded
[    0.360835] ACPI: [Firmware Bug]: BIOS _OSI(Linux) query ignored
[    0.365164] ACPI: EC: EC started
[    0.365165] ACPI: EC: interrupt blocked
[    0.365229] ACPI: EC: EC_CMD/EC_SC=0x66, EC_DATA=0x62
[    0.365231] ACPI: \_SB_.PCI0.SBRG.EC0_: Boot DSDT EC used to handle transactions
[    0.365232] ACPI: Interpreter enabled
[    0.365246] ACPI: PM: (supports S0 S4 S5)
[    0.365247] ACPI: Using IOAPIC for interrupt routing
[    0.365452] PCI: Using host bridge windows from ACPI; if necessary, use "pci=nocrs" and report a bug
[    0.365453] PCI: Using E820 reservations for host bridge windows
[    0.366121] ACPI: PM: Power Resource [PG00]
[    0.366506] ACPI: PM: Power Resource [WRST]
[    0.366807] ACPI: PM: Power Resource [P0U0]
[    0.366864] ACPI: PM: Power Resource [P3U0]
[    0.367360] ACPI: PM: Power Resource [P0U1]
[    0.367414] ACPI: PM: Power Resource [P3U1]
[    0.368462] ACPI: PM: Power Resource [P0NV]
[    0.371506] ACPI: PM: Power Resource [P1NV]
[    0.377078] ACPI: PM: Power Resource [QFAN]
[    0.377430] ACPI: PCI Root Bridge [PCI0] (domain 0000 [bus 00-ff])
[    0.377434] acpi PNP0A08:00: _OSC: OS supports [ExtendedConfig ASPM ClockPM Segments MSI EDR HPX-Type3]
[    0.377492] acpi PNP0A08:00: _OSC: platform does not support [SHPCHotplug LTR DPC]
[    0.377594] acpi PNP0A08:00: _OSC: OS now controls [PCIeHotplug PME AER PCIeCapability]
[    0.377602] acpi PNP0A08:00: [Firmware Info]: MMCONFIG for domain 0000 [bus 00-7f] only partially covers this bridge
[    0.377890] PCI host bridge to bus 0000:00
[    0.377891] pci_bus 0000:00: root bus resource [io  0x0000-0x03af window]
[    0.377892] pci_bus 0000:00: root bus resource [io  0x03e0-0x0cf7 window]
[    0.377892] pci_bus 0000:00: root bus resource [io  0x03b0-0x03df window]
[    0.377893] pci_bus 0000:00: root bus resource [io  0x0d00-0xffff window]
[    0.377894] pci_bus 0000:00: root bus resource [mem 0x000a0000-0x000dffff window]
[    0.377895] pci_bus 0000:00: root bus resource [mem 0xf0000000-0xfcffffff window]
[    0.377895] pci_bus 0000:00: root bus resource [mem 0x1010000000-0xffffffffff window]
[    0.377896] pci_bus 0000:00: root bus resource [bus 00-ff]
[    0.377907] pci 0000:00:00.0: [1022:1630] type 00 class 0x060000
[    0.377973] pci 0000:00:00.2: [1022:1631] type 00 class 0x080600
[    0.378043] pci 0000:00:01.0: [1022:1632] type 00 class 0x060000
[    0.378104] pci 0000:00:01.1: [1022:1633] type 01 class 0x060400
[    0.378226] pci 0000:00:01.1: PME# supported from D0 D3hot D3cold
[    0.378321] pci 0000:00:02.0: [1022:1632] type 00 class 0x060000
[    0.378370] pci 0000:00:02.1: [1022:1634] type 01 class 0x060400
[    0.378390] pci 0000:00:02.1: enabling Extended Tags
[    0.378417] pci 0000:00:02.1: PME# supported from D0 D3hot D3cold
[    0.378462] pci 0000:00:02.2: [1022:1634] type 01 class 0x060400
[    0.378483] pci 0000:00:02.2: enabling Extended Tags
[    0.378509] pci 0000:00:02.2: PME# supported from D0 D3hot D3cold
[    0.378556] pci 0000:00:02.3: [1022:1634] type 01 class 0x060400
[    0.378576] pci 0000:00:02.3: enabling Extended Tags
[    0.378603] pci 0000:00:02.3: PME# supported from D0 D3hot D3cold
[    0.378646] pci 0000:00:02.4: [1022:1634] type 01 class 0x060400
[    0.378691] pci 0000:00:02.4: PME# supported from D0 D3hot D3cold
[    0.378746] pci 0000:00:08.0: [1022:1632] type 00 class 0x060000
[    0.378793] pci 0000:00:08.1: [1022:1635] type 01 class 0x060400
[    0.378812] pci 0000:00:08.1: enabling Extended Tags
[    0.378838] pci 0000:00:08.1: PME# supported from D0 D3hot D3cold
[    0.378922] pci 0000:00:14.0: [1022:790b] type 00 class 0x0c0500
[    0.379020] pci 0000:00:14.3: [1022:790e] type 00 class 0x060100
[    0.379126] pci 0000:00:18.0: [1022:166a] type 00 class 0x060000
[    0.379154] pci 0000:00:18.1: [1022:166b] type 00 class 0x060000
[    0.379186] pci 0000:00:18.2: [1022:166c] type 00 class 0x060000
[    0.379215] pci 0000:00:18.3: [1022:166d] type 00 class 0x060000
[    0.379244] pci 0000:00:18.4: [1022:166e] type 00 class 0x060000
[    0.379275] pci 0000:00:18.5: [1022:166f] type 00 class 0x060000
[    0.379304] pci 0000:00:18.6: [1022:1670] type 00 class 0x060000
[    0.379334] pci 0000:00:18.7: [1022:1671] type 00 class 0x060000
[    0.379425] pci 0000:00:01.1: PCI bridge to [bus 01]
[    0.379430] pci 0000:00:01.1:   bridge window [io  0xf000-0xffff]
[    0.379434] pci 0000:00:01.1:   bridge window [mem 0xfb000000-0xfc0fffff]
[    0.379439] pci 0000:00:01.1:   bridge window [mem 0xfc00000000-0xfe01ffffff 64bit pref]
[    0.379478] pci 0000:02:00.0: [10ec:8168] type 00 class 0x020000
[    0.379495] pci 0000:02:00.0: reg 0x10: [io  0xe000-0xe0ff]
[    0.379516] pci 0000:02:00.0: reg 0x18: [mem 0xfc904000-0xfc904fff 64bit]
[    0.379529] pci 0000:02:00.0: reg 0x20: [mem 0xfc900000-0xfc903fff 64bit]
[    0.379613] pci 0000:02:00.0: supports D1 D2
[    0.379614] pci 0000:02:00.0: PME# supported from D0 D1 D2 D3hot D3cold
[    0.379711] pci 0000:00:02.1: PCI bridge to [bus 02]
[    0.379713] pci 0000:00:02.1:   bridge window [io  0xe000-0xefff]
[    0.379715] pci 0000:00:02.1:   bridge window [mem 0xfc900000-0xfc9fffff]
[    0.379788] pci 0000:03:00.0: [8086:2723] type 00 class 0x028000
[    0.379820] pci 0000:03:00.0: reg 0x10: [mem 0xfc800000-0xfc803fff 64bit]
[    0.379937] pci 0000:03:00.0: PME# supported from D0 D3hot D3cold
[    0.380062] pci 0000:00:02.2: PCI bridge to [bus 03]
[    0.380066] pci 0000:00:02.2:   bridge window [mem 0xfc800000-0xfc8fffff]
[    0.380102] pci 0000:04:00.0: [144d:a808] type 00 class 0x010802
[    0.380119] pci 0000:04:00.0: reg 0x10: [mem 0xfc700000-0xfc703fff 64bit]
[    0.380293] pci 0000:00:02.3: PCI bridge to [bus 04]
[    0.380296] pci 0000:00:02.3:   bridge window [mem 0xfc700000-0xfc7fffff]
[    0.380367] pci 0000:05:00.0: [2646:500e] type 00 class 0x010802
[    0.380385] pci 0000:05:00.0: reg 0x10: [mem 0xfc600000-0xfc603fff 64bit]
[    0.380587] pci 0000:00:02.4: PCI bridge to [bus 05]
[    0.380591] pci 0000:00:02.4:   bridge window [mem 0xfc600000-0xfc6fffff]
[    0.380640] pci 0000:06:00.0: [1002:1638] type 00 class 0x030000
[    0.380650] pci 0000:06:00.0: reg 0x10: [mem 0xfe10000000-0xfe1fffffff 64bit pref]
[    0.380657] pci 0000:06:00.0: reg 0x18: [mem 0xfe20000000-0xfe201fffff 64bit pref]
[    0.380661] pci 0000:06:00.0: reg 0x20: [io  0xd000-0xd0ff]
[    0.380666] pci 0000:06:00.0: reg 0x24: [mem 0xfc500000-0xfc57ffff]
[    0.380673] pci 0000:06:00.0: enabling Extended Tags
[    0.380682] pci 0000:06:00.0: BAR 0: assigned to efifb
[    0.380716] pci 0000:06:00.0: PME# supported from D1 D2 D3hot D3cold
[    0.380746] pci 0000:06:00.0: 126.016 Gb/s available PCIe bandwidth, limited by 8.0 GT/s PCIe x16 link at 0000:00:08.1 (capable of 252.048 Gb/s with 16.0 GT/s PCIe x16 link)
[    0.380780] pci 0000:06:00.1: [1002:1637] type 00 class 0x040300
[    0.380787] pci 0000:06:00.1: reg 0x10: [mem 0xfc5c8000-0xfc5cbfff]
[    0.380806] pci 0000:06:00.1: enabling Extended Tags
[    0.380831] pci 0000:06:00.1: PME# supported from D1 D2 D3hot D3cold
[    0.380869] pci 0000:06:00.2: [1022:15df] type 00 class 0x108000
[    0.380881] pci 0000:06:00.2: reg 0x18: [mem 0xfc400000-0xfc4fffff]
[    0.380889] pci 0000:06:00.2: reg 0x24: [mem 0xfc5cc000-0xfc5cdfff]
[    0.380895] pci 0000:06:00.2: enabling Extended Tags
[    0.380958] pci 0000:06:00.3: [1022:1639] type 00 class 0x0c0330
[    0.380968] pci 0000:06:00.3: reg 0x10: [mem 0xfc300000-0xfc3fffff 64bit]
[    0.380989] pci 0000:06:00.3: enabling Extended Tags
[    0.381016] pci 0000:06:00.3: PME# supported from D0 D3hot D3cold
[    0.381063] pci 0000:06:00.4: [1022:1639] type 00 class 0x0c0330
[    0.381073] pci 0000:06:00.4: reg 0x10: [mem 0xfc200000-0xfc2fffff 64bit]
[    0.381095] pci 0000:06:00.4: enabling Extended Tags
[    0.381122] pci 0000:06:00.4: PME# supported from D0 D3hot D3cold
[    0.381165] pci 0000:06:00.5: [1022:15e2] type 00 class 0x048000
[    0.381172] pci 0000:06:00.5: reg 0x10: [mem 0xfc580000-0xfc5bffff]
[    0.381190] pci 0000:06:00.5: enabling Extended Tags
[    0.381215] pci 0000:06:00.5: PME# supported from D0 D3hot D3cold
[    0.381255] pci 0000:06:00.6: [1022:15e3] type 00 class 0x040300
[    0.381262] pci 0000:06:00.6: reg 0x10: [mem 0xfc5c0000-0xfc5c7fff]
[    0.381281] pci 0000:06:00.6: enabling Extended Tags
[    0.381306] pci 0000:06:00.6: PME# supported from D0 D3hot D3cold
[    0.381360] pci 0000:00:08.1: PCI bridge to [bus 06]
[    0.381363] pci 0000:00:08.1:   bridge window [io  0xd000-0xdfff]
[    0.381364] pci 0000:00:08.1:   bridge window [mem 0xfc200000-0xfc5fffff]
[    0.381366] pci 0000:00:08.1:   bridge window [mem 0xfe10000000-0xfe201fffff 64bit pref]
[    0.382052] ACPI: PCI: Interrupt link LNKA configured for IRQ 0
[    0.382090] ACPI: PCI: Interrupt link LNKB configured for IRQ 0
[    0.382122] ACPI: PCI: Interrupt link LNKC configured for IRQ 0
[    0.382162] ACPI: PCI: Interrupt link LNKD configured for IRQ 0
[    0.382198] ACPI: PCI: Interrupt link LNKE configured for IRQ 0
[    0.382228] ACPI: PCI: Interrupt link LNKF configured for IRQ 0
[    0.382258] ACPI: PCI: Interrupt link LNKG configured for IRQ 0
[    0.382287] ACPI: PCI: Interrupt link LNKH configured for IRQ 0
[    0.382971] Low-power S0 idle used by default for system suspend
[    0.383084] ACPI: EC: interrupt unblocked
[    0.383085] ACPI: EC: event unblocked
[    0.383093] ACPI: EC: EC_CMD/EC_SC=0x66, EC_DATA=0x62
[    0.383094] ACPI: EC: GPE=0x3
[    0.383094] ACPI: \_SB_.PCI0.SBRG.EC0_: Boot DSDT EC initialization complete
[    0.383095] ACPI: \_SB_.PCI0.SBRG.EC0_: EC: Used to handle transactions and events
[    0.383119] iommu: Default domain type: Translated 
[    0.383120] iommu: DMA domain TLB invalidation policy: lazy mode 
[    0.383198] SCSI subsystem initialized
[    0.383203] libata version 3.00 loaded.
[    0.383203] ACPI: bus type USB registered
[    0.383203] usbcore: registered new interface driver usbfs
[    0.383203] usbcore: registered new interface driver hub
[    0.383203] usbcore: registered new device driver usb
[    0.384812] pps_core: LinuxPPS API ver. 1 registered
[    0.384813] pps_core: Software ver. 5.3.6 - Copyright 2005-2007 Rodolfo Giometti <giometti@linux.it>
[    0.384814] PTP clock support registered
[    0.384819] EDAC MC: Ver: 3.0.0
[    0.384923] Registered efivars operations
[    0.384923] NetLabel: Initializing
[    0.384923] NetLabel:  domain hash size = 128
[    0.384923] NetLabel:  protocols = UNLABELED CIPSOv4 CALIPSO
[    0.384923] NetLabel:  unlabeled traffic allowed by default
[    0.384923] mctp: management component transport protocol core
[    0.384923] NET: Registered PF_MCTP protocol family
[    0.384923] PCI: Using ACPI for IRQ routing
[    0.389190] PCI: pci_cache_line_size set to 64 bytes
[    0.389328] Expanded resource Reserved due to conflict with PCI Bus 0000:00
[    0.389330] e820: reserve RAM buffer [mem 0x09bff000-0x0bffffff]
[    0.389331] e820: reserve RAM buffer [mem 0x0a200000-0x0bffffff]
[    0.389332] e820: reserve RAM buffer [mem 0xdf1ac018-0xdfffffff]
[    0.389332] e820: reserve RAM buffer [mem 0xdf1ba018-0xdfffffff]
[    0.389333] e820: reserve RAM buffer [mem 0xe7d72000-0xe7ffffff]
[    0.389333] e820: reserve RAM buffer [mem 0xe9a46000-0xebffffff]
[    0.389334] e820: reserve RAM buffer [mem 0xeaed4000-0xebffffff]
[    0.389334] e820: reserve RAM buffer [mem 0xee000000-0xefffffff]
[    0.389335] e820: reserve RAM buffer [mem 0xfee300000-0xfefffffff]
[    0.389341] pci 0000:06:00.0: vgaarb: setting as boot VGA device
[    0.389341] pci 0000:06:00.0: vgaarb: bridge control possible
[    0.389341] pci 0000:06:00.0: vgaarb: VGA device added: decodes=io+mem,owns=none,locks=none
[    0.389341] vgaarb: loaded
[    0.389341] hpet0: at MMIO 0xfed00000, IRQs 2, 8, 0
[    0.389341] hpet0: 3 comparators, 32-bit 14.318180 MHz counter
[    0.391453] clocksource: Switched to clocksource tsc-early
[    0.391512] VFS: Disk quotas dquot_6.6.0
[    0.391519] VFS: Dquot-cache hash table entries: 512 (order 0, 4096 bytes)
[    0.391557] pnp: PnP ACPI init
[    0.391614] system 00:00: [mem 0xf0000000-0xf7ffffff] has been reserved
[    0.391900] system 00:03: [io  0x04d0-0x04d1] has been reserved
[    0.391901] system 00:03: [io  0x040b] has been reserved
[    0.391902] system 00:03: [io  0x04d6] has been reserved
[    0.391903] system 00:03: [io  0x0c00-0x0c01] has been reserved
[    0.391903] system 00:03: [io  0x0c14] has been reserved
[    0.391904] system 00:03: [io  0x0c50-0x0c51] has been reserved
[    0.391905] system 00:03: [io  0x0c52] has been reserved
[    0.391905] system 00:03: [io  0x0c6c] has been reserved
[    0.391906] system 00:03: [io  0x0c6f] has been reserved
[    0.391907] system 00:03: [io  0x0cd8-0x0cdf] has been reserved
[    0.391907] system 00:03: [io  0x0800-0x089f] has been reserved
[    0.391908] system 00:03: [io  0x0b00-0x0b0f] has been reserved
[    0.391908] system 00:03: [io  0x0b20-0x0b3f] has been reserved
[    0.391909] system 00:03: [io  0x0900-0x090f] has been reserved
[    0.391910] system 00:03: [io  0x0910-0x091f] has been reserved
[    0.391911] system 00:03: [mem 0xfec00000-0xfec00fff] could not be reserved
[    0.391912] system 00:03: [mem 0xfec01000-0xfec01fff] could not be reserved
[    0.391913] system 00:03: [mem 0xfedc0000-0xfedc0fff] has been reserved
[    0.391914] system 00:03: [mem 0xfee00000-0xfee00fff] has been reserved
[    0.391915] system 00:03: [mem 0xfed80000-0xfed8ffff] could not be reserved
[    0.391916] system 00:03: [mem 0xfec10000-0xfec10fff] has been reserved
[    0.391916] system 00:03: [mem 0xff000000-0xffffffff] has been reserved
[    0.392427] pnp: PnP ACPI: found 4 devices
[    0.397520] clocksource: acpi_pm: mask: 0xffffff max_cycles: 0xffffff, max_idle_ns: 2085701024 ns
[    0.397560] NET: Registered PF_INET protocol family
[    0.397710] IP idents hash table entries: 262144 (order: 9, 2097152 bytes, linear)
[    0.400218] tcp_listen_portaddr_hash hash table entries: 32768 (order: 7, 524288 bytes, linear)
[    0.400257] Table-perturb hash table entries: 65536 (order: 6, 262144 bytes, linear)
[    0.400515] TCP established hash table entries: 524288 (order: 10, 4194304 bytes, linear)
[    0.400831] TCP bind hash table entries: 65536 (order: 8, 1048576 bytes, linear)
[    0.400878] TCP: Hash tables configured (established 524288 bind 65536)
[    0.401039] MPTCP token hash table entries: 65536 (order: 8, 1572864 bytes, linear)
[    0.401147] UDP hash table entries: 32768 (order: 8, 1048576 bytes, linear)
[    0.401262] UDP-Lite hash table entries: 32768 (order: 8, 1048576 bytes, linear)
[    0.401369] NET: Registered PF_UNIX/PF_LOCAL protocol family
[    0.401372] NET: Registered PF_XDP protocol family
[    0.401379] pci 0000:00:01.1: PCI bridge to [bus 01]
[    0.401383] pci 0000:00:01.1:   bridge window [io  0xf000-0xffff]
[    0.401388] pci 0000:00:01.1:   bridge window [mem 0xfb000000-0xfc0fffff]
[    0.401390] pci 0000:00:01.1:   bridge window [mem 0xfc00000000-0xfe01ffffff 64bit pref]
[    0.401396] pci 0000:00:02.1: PCI bridge to [bus 02]
[    0.401397] pci 0000:00:02.1:   bridge window [io  0xe000-0xefff]
[    0.401399] pci 0000:00:02.1:   bridge window [mem 0xfc900000-0xfc9fffff]
[    0.401403] pci 0000:00:02.2: PCI bridge to [bus 03]
[    0.401405] pci 0000:00:02.2:   bridge window [mem 0xfc800000-0xfc8fffff]
[    0.401408] pci 0000:00:02.3: PCI bridge to [bus 04]
[    0.401410] pci 0000:00:02.3:   bridge window [mem 0xfc700000-0xfc7fffff]
[    0.401414] pci 0000:00:02.4: PCI bridge to [bus 05]
[    0.401415] pci 0000:00:02.4:   bridge window [mem 0xfc600000-0xfc6fffff]
[    0.401419] pci 0000:00:08.1: PCI bridge to [bus 06]
[    0.401420] pci 0000:00:08.1:   bridge window [io  0xd000-0xdfff]
[    0.401422] pci 0000:00:08.1:   bridge window [mem 0xfc200000-0xfc5fffff]
[    0.401424] pci 0000:00:08.1:   bridge window [mem 0xfe10000000-0xfe201fffff 64bit pref]
[    0.401427] pci_bus 0000:00: resource 4 [io  0x0000-0x03af window]
[    0.401428] pci_bus 0000:00: resource 5 [io  0x03e0-0x0cf7 window]
[    0.401429] pci_bus 0000:00: resource 6 [io  0x03b0-0x03df window]
[    0.401429] pci_bus 0000:00: resource 7 [io  0x0d00-0xffff window]
[    0.401430] pci_bus 0000:00: resource 8 [mem 0x000a0000-0x000dffff window]
[    0.401431] pci_bus 0000:00: resource 9 [mem 0xf0000000-0xfcffffff window]
[    0.401431] pci_bus 0000:00: resource 10 [mem 0x1010000000-0xffffffffff window]
[    0.401432] pci_bus 0000:01: resource 0 [io  0xf000-0xffff]
[    0.401433] pci_bus 0000:01: resource 1 [mem 0xfb000000-0xfc0fffff]
[    0.401433] pci_bus 0000:01: resource 2 [mem 0xfc00000000-0xfe01ffffff 64bit pref]
[    0.401434] pci_bus 0000:02: resource 0 [io  0xe000-0xefff]
[    0.401435] pci_bus 0000:02: resource 1 [mem 0xfc900000-0xfc9fffff]
[    0.401435] pci_bus 0000:03: resource 1 [mem 0xfc800000-0xfc8fffff]
[    0.401436] pci_bus 0000:04: resource 1 [mem 0xfc700000-0xfc7fffff]
[    0.401437] pci_bus 0000:05: resource 1 [mem 0xfc600000-0xfc6fffff]
[    0.401437] pci_bus 0000:06: resource 0 [io  0xd000-0xdfff]
[    0.401438] pci_bus 0000:06: resource 1 [mem 0xfc200000-0xfc5fffff]
[    0.401438] pci_bus 0000:06: resource 2 [mem 0xfe10000000-0xfe201fffff 64bit pref]
[    0.401568] pci 0000:06:00.1: D0 power state depends on 0000:06:00.0
[    0.401591] pci 0000:06:00.3: extending delay after power-on from D3hot to 20 msec
[    0.401702] pci 0000:06:00.4: extending delay after power-on from D3hot to 20 msec
[    0.401750] PCI: CLS 64 bytes, default 64
[    0.401757] pci 0000:00:00.2: AMD-Vi: IOMMU performance counters supported
[    0.401781] Trying to unpack rootfs image as initramfs...
[    0.401784] pci 0000:00:00.2: can't derive routing for PCI INT A
[    0.401785] pci 0000:00:00.2: PCI INT A: not connected
[    0.401799] pci 0000:00:01.0: Adding to iommu group 0
[    0.401807] pci 0000:00:01.1: Adding to iommu group 1
[    0.401816] pci 0000:00:02.0: Adding to iommu group 2
[    0.401821] pci 0000:00:02.1: Adding to iommu group 3
[    0.401826] pci 0000:00:02.2: Adding to iommu group 4
[    0.401832] pci 0000:00:02.3: Adding to iommu group 5
[    0.401837] pci 0000:00:02.4: Adding to iommu group 6
[    0.401845] pci 0000:00:08.0: Adding to iommu group 7
[    0.401849] pci 0000:00:08.1: Adding to iommu group 7
[    0.401856] pci 0000:00:14.0: Adding to iommu group 8
[    0.401860] pci 0000:00:14.3: Adding to iommu group 8
[    0.401875] pci 0000:00:18.0: Adding to iommu group 9
[    0.401880] pci 0000:00:18.1: Adding to iommu group 9
[    0.401884] pci 0000:00:18.2: Adding to iommu group 9
[    0.401889] pci 0000:00:18.3: Adding to iommu group 9
[    0.401893] pci 0000:00:18.4: Adding to iommu group 9
[    0.401898] pci 0000:00:18.5: Adding to iommu group 9
[    0.401902] pci 0000:00:18.6: Adding to iommu group 9
[    0.401907] pci 0000:00:18.7: Adding to iommu group 9
[    0.401913] pci 0000:02:00.0: Adding to iommu group 10
[    0.401919] pci 0000:03:00.0: Adding to iommu group 11
[    0.401924] pci 0000:04:00.0: Adding to iommu group 12
[    0.401930] pci 0000:05:00.0: Adding to iommu group 13
[    0.401941] pci 0000:06:00.0: Adding to iommu group 7
[    0.401943] pci 0000:06:00.1: Adding to iommu group 7
[    0.401946] pci 0000:06:00.2: Adding to iommu group 7
[    0.401949] pci 0000:06:00.3: Adding to iommu group 7
[    0.401951] pci 0000:06:00.4: Adding to iommu group 7
[    0.401954] pci 0000:06:00.5: Adding to iommu group 7
[    0.401957] pci 0000:06:00.6: Adding to iommu group 7
[    0.402930] pci 0000:00:00.2: AMD-Vi: Found IOMMU cap 0x40
[    0.402931] AMD-Vi: Extended features (0x206d73ef22254ade, 0x0): PPR X2APIC NX GT IA GA PC GA_vAPIC
[    0.402935] AMD-Vi: Interrupt remapping enabled
[    0.402935] AMD-Vi: X2APIC enabled
[    0.415491] AMD-Vi: Virtual APIC enabled
[    0.415539] PCI-DMA: Using software bounce buffering for IO (SWIOTLB)
[    0.415541] software IO TLB: mapped [mem 0x00000000db1ac000-0x00000000df1ac000] (64MB)
[    0.415563] LVT offset 0 assigned for vector 0x400
[    0.415648] perf: AMD IBS detected (0x000003ff)
[    0.415653] perf/amd_iommu: Detected AMD IOMMU #0 (2 banks, 4 counters/bank).
[    0.416583] Initialise system trusted keyrings
[    0.416590] Key type blacklist registered
[    0.416613] workingset: timestamp_bits=41 max_order=24 bucket_order=0
[    0.417202] zbud: loaded
[    0.417298] integrity: Platform Keyring initialized
[    0.417300] integrity: Machine keyring initialized
[    0.419879] Key type asymmetric registered
[    0.419880] Asymmetric key parser 'x509' registered
[    0.430374] Freeing initrd memory: 8868K
[    0.431784] alg: self-tests for CTR-KDF (hmac(sha256)) passed
[    0.431799] Block layer SCSI generic (bsg) driver version 0.4 loaded (major 243)
[    0.431823] io scheduler mq-deadline registered
[    0.431824] io scheduler kyber registered
[    0.431842] io scheduler bfq registered
[    0.432054] amd_gpio AMDI0030:00: failed to get iomux index
[    0.433073] pcieport 0000:00:01.1: PME: Signaling with IRQ 34
[    0.433092] pcieport 0000:00:01.1: pciehp: Slot #0 AttnBtn- PwrCtrl- MRL- AttnInd- PwrInd- HotPlug+ Surprise+ Interlock- NoCompl+ IbPresDis- LLActRep+
[    0.433243] pcieport 0000:00:02.1: PME: Signaling with IRQ 35
[    0.433316] pcieport 0000:00:02.2: PME: Signaling with IRQ 36
[    0.433388] pcieport 0000:00:02.3: PME: Signaling with IRQ 37
[    0.433468] pcieport 0000:00:02.4: PME: Signaling with IRQ 38
[    0.433546] pcieport 0000:00:08.1: PME: Signaling with IRQ 39
[    0.433607] shpchp: Standard Hot Plug PCI Controller Driver version: 0.4
[    0.435544] ACPI: AC: AC Adapter [ACAD] (on-line)
[    0.435570] input: Power Button as /devices/LNXSYSTM:00/LNXSYBUS:00/PNP0C0C:00/input/input0
[    0.435580] ACPI: button: Power Button [PWRB]
[    0.435594] input: Sleep Button as /devices/LNXSYSTM:00/LNXSYBUS:00/PNP0C0E:00/input/input1
[    0.435600] ACPI: button: Sleep Button [SLPB]
[    0.435611] input: Lid Switch as /devices/LNXSYSTM:00/LNXSYBUS:00/PNP0C0D:00/input/input2
[    0.435617] ACPI: button: Lid Switch [LID0]
[    0.435685] Estimated ratio of average max frequency by base frequency (times 1024): 1226
[    0.435696] Monitor-Mwait will be used to enter C-1 state
[    0.435699] ACPI: \_SB_.PLTF.P000: Found 3 idle states
[    0.435758] ACPI: \_SB_.PLTF.P001: Found 3 idle states
[    0.435820] ACPI: \_SB_.PLTF.P002: Found 3 idle states
[    0.435878] ACPI: \_SB_.PLTF.P003: Found 3 idle states
[    0.435939] ACPI: \_SB_.PLTF.P004: Found 3 idle states
[    0.435997] ACPI: \_SB_.PLTF.P005: Found 3 idle states
[    0.436059] ACPI: \_SB_.PLTF.P006: Found 3 idle states
[    0.436123] ACPI: \_SB_.PLTF.P007: Found 3 idle states
[    0.436169] ACPI: \_SB_.PLTF.P008: Found 3 idle states
[    0.436230] ACPI: \_SB_.PLTF.P009: Found 3 idle states
[    0.436277] ACPI: \_SB_.PLTF.P00A: Found 3 idle states
[    0.436353] ACPI: \_SB_.PLTF.P00B: Found 3 idle states
[    0.436432] ACPI: \_SB_.PLTF.P00C: Found 3 idle states
[    0.436505] ACPI: \_SB_.PLTF.P00D: Found 3 idle states
[    0.436583] ACPI: \_SB_.PLTF.P00E: Found 3 idle states
[    0.436648] ACPI: \_SB_.PLTF.P00F: Found 3 idle states
[    0.436805] ACPI: \_TZ_.THRM: Invalid passive threshold
[    0.436863] ACPI BIOS Error (bug): Could not resolve symbol [\_TZ.THRM._SCP.CTYP], AE_NOT_FOUND (20220331/psargs-330)
[    0.436869] fbcon: Taking over console
[    0.436874] ACPI Error: Aborting method \_TZ.THRM._SCP due to previous error (AE_NOT_FOUND) (20220331/psparse-529)
[    0.436939] thermal LNXTHERM:00: registered as thermal_zone0
[    0.436940] ACPI: thermal: Thermal Zone [THRM] (64 C)
[    0.437024] Serial: 8250/16550 driver, 32 ports, IRQ sharing enabled
[    0.437294] ACPI: battery: Slot [BAT1] (battery present)
[    0.437640] Non-volatile memory driver v1.3
[    0.437641] Linux agpgart interface v0.103
[    0.437658] AMD-Vi: AMD IOMMUv2 loaded and initialized
[    0.437676] ACPI: bus type drm_connector registered
[    0.438235] ehci_hcd: USB 2.0 'Enhanced' Host Controller (EHCI) Driver
[    0.438237] ehci-pci: EHCI PCI platform driver
[    0.438241] ohci_hcd: USB 1.1 'Open' Host Controller (OHCI) Driver
[    0.438243] ohci-pci: OHCI PCI platform driver
[    0.438246] uhci_hcd: USB Universal Host Controller Interface driver
[    0.438266] usbcore: registered new interface driver usbserial_generic
[    0.438268] usbserial: USB Serial support registered for generic
[    0.438316] rtc_cmos 00:01: RTC can wake from S4
[    0.438523] rtc_cmos 00:01: registered as rtc0
[    0.438551] rtc_cmos 00:01: setting system clock to 2022-10-27T23:24:48 UTC (1666913088)
[    0.438559] rtc_cmos 00:01: alarms up to one month, y3k, 114 bytes nvram, hpet irqs
[    0.438712] ledtrig-cpu: registered to indicate activity on CPUs
[    0.438782] efifb: probing for efifb
[    0.438825] efifb: framebuffer at 0xfe10000000, using 8100k, total 8100k
[    0.438825] efifb: mode is 1920x1080x32, linelength=7680, pages=1
[    0.438826] efifb: scrolling: redraw
[    0.438827] efifb: Truecolor: size=8:8:8:8, shift=24:16:8:0
[    0.438877] Console: switching to colour frame buffer device 240x67
[    0.462509] fb0: EFI VGA frame buffer device
[    0.462523] hid: raw HID events driver (C) Jiri Kosina
[    0.462562] drop_monitor: Initializing network drop monitor service
[    0.469109] Initializing XFRM netlink socket
[    0.469152] NET: Registered PF_INET6 protocol family
[    0.471300] Segment Routing with IPv6
[    0.471301] RPL Segment Routing with IPv6
[    0.471306] In-situ OAM (IOAM) with IPv6
[    0.471318] NET: Registered PF_PACKET protocol family
[    0.471974] microcode: CPU0: patch_level=0x0a50000c
[    0.471979] microcode: CPU1: patch_level=0x0a50000c
[    0.471993] microcode: CPU2: patch_level=0x0a50000c
[    0.471998] microcode: CPU3: patch_level=0x0a50000c
[    0.472012] microcode: CPU4: patch_level=0x0a50000c
[    0.472017] microcode: CPU5: patch_level=0x0a50000c
[    0.472021] microcode: CPU6: patch_level=0x0a50000c
[    0.472025] microcode: CPU7: patch_level=0x0a50000c
[    0.472030] microcode: CPU8: patch_level=0x0a50000c
[    0.472035] microcode: CPU9: patch_level=0x0a50000c
[    0.472048] microcode: CPU10: patch_level=0x0a50000c
[    0.472053] microcode: CPU11: patch_level=0x0a50000c
[    0.472067] microcode: CPU12: patch_level=0x0a50000c
[    0.472071] microcode: CPU13: patch_level=0x0a50000c
[    0.472085] microcode: CPU14: patch_level=0x0a50000c
[    0.472090] microcode: CPU15: patch_level=0x0a50000c
[    0.472092] microcode: Microcode Update Driver: v2.2.
[    0.472259] resctrl: L3 allocation detected
[    0.472260] resctrl: MB allocation detected
[    0.472261] resctrl: L3 monitoring detected
[    0.472264] IPI shorthand broadcast: enabled
[    0.472283] sched_clock: Marking stable (471992785, 261061)->(473346578, -1092732)
[    0.472523] registered taskstats version 1
[    0.472755] Loading compiled-in X.509 certificates
[    0.474616] Loaded X.509 cert 'Build time autogenerated kernel key: fb0ed67bba175219c33bcebf118983ec9276353f'
[    0.474981] zswap: loaded using pool lz4/z3fold
[    0.475104] Key type ._fscrypt registered
[    0.475105] Key type .fscrypt registered
[    0.475105] Key type fscrypt-provisioning registered
[    0.476230] PM:   Magic number: 10:869:454
[    0.476372] RAS: Correctable Errors collector initialized.
[    0.492645] Freeing unused decrypted memory: 2036K
[    0.492839] Freeing unused kernel image (initmem) memory: 2120K
[    0.524777] Write protecting the kernel read-only data: 28672k
[    0.525430] Freeing unused kernel image (text/rodata gap) memory: 2040K
[    0.525588] Freeing unused kernel image (rodata/data gap) memory: 968K
[    0.547628] x86/mm: Checked W+X mappings: passed, no W+X pages found.
[    0.547632] rodata_test: all tests were successful
[    0.547637] Run /init as init process
[    0.547638]   with arguments:
[    0.547639]     /init
[    0.547639]   with environment:
[    0.547640]     HOME=/
[    0.547640]     TERM=linux
[    0.617468] i8042: PNP: PS/2 Controller [PNP0303:PS2K] at 0x60,0x64 irq 1
[    0.617472] i8042: PNP: PS/2 appears to have AUX port disabled, if this is incorrect please boot with i8042.nopnp
[    0.618590] serio: i8042 KBD port at 0x60,0x64 irq 1
[    0.620237] xhci_hcd 0000:06:00.3: xHCI Host Controller
[    0.620243] xhci_hcd 0000:06:00.3: new USB bus registered, assigned bus number 1
[    0.620327] xhci_hcd 0000:06:00.3: hcc params 0x0268ffe5 hci version 0x110 quirks 0x0000020000000410
[    0.620605] xhci_hcd 0000:06:00.3: xHCI Host Controller
[    0.620607] xhci_hcd 0000:06:00.3: new USB bus registered, assigned bus number 2
[    0.620609] xhci_hcd 0000:06:00.3: Host supports USB 3.1 Enhanced SuperSpeed
[    0.620650] usb usb1: New USB device found, idVendor=1d6b, idProduct=0002, bcdDevice= 6.00
[    0.620652] usb usb1: New USB device strings: Mfr=3, Product=2, SerialNumber=1
[    0.620653] usb usb1: Product: xHCI Host Controller
[    0.620654] usb usb1: Manufacturer: Linux 6.0.1-arch2-1 xhci-hcd
[    0.620655] usb usb1: SerialNumber: 0000:06:00.3
[    0.620737] hub 1-0:1.0: USB hub found
[    0.620744] hub 1-0:1.0: 4 ports detected
[    0.621944] usb usb2: We don't know the algorithms for LPM for this host, disabling LPM.
[    0.621957] usb usb2: New USB device found, idVendor=1d6b, idProduct=0003, bcdDevice= 6.00
[    0.621958] usb usb2: New USB device strings: Mfr=3, Product=2, SerialNumber=1
[    0.621960] usb usb2: Product: xHCI Host Controller
[    0.621960] usb usb2: Manufacturer: Linux 6.0.1-arch2-1 xhci-hcd
[    0.621961] usb usb2: SerialNumber: 0000:06:00.3
[    0.622006] hub 2-0:1.0: USB hub found
[    0.622011] hub 2-0:1.0: 2 ports detected
[    0.622384] xhci_hcd 0000:06:00.4: xHCI Host Controller
[    0.622389] xhci_hcd 0000:06:00.4: new USB bus registered, assigned bus number 3
[    0.622470] xhci_hcd 0000:06:00.4: hcc params 0x0268ffe5 hci version 0x110 quirks 0x0000020000000410
[    0.622707] xhci_hcd 0000:06:00.4: xHCI Host Controller
[    0.622709] xhci_hcd 0000:06:00.4: new USB bus registered, assigned bus number 4
[    0.622710] xhci_hcd 0000:06:00.4: Host supports USB 3.1 Enhanced SuperSpeed
[    0.622729] usb usb3: New USB device found, idVendor=1d6b, idProduct=0002, bcdDevice= 6.00
[    0.622730] usb usb3: New USB device strings: Mfr=3, Product=2, SerialNumber=1
[    0.622731] usb usb3: Product: xHCI Host Controller
[    0.622731] usb usb3: Manufacturer: Linux 6.0.1-arch2-1 xhci-hcd
[    0.622732] usb usb3: SerialNumber: 0000:06:00.4
[    0.622780] hub 3-0:1.0: USB hub found
[    0.622785] hub 3-0:1.0: 4 ports detected
[    0.623250] usb usb4: We don't know the algorithms for LPM for this host, disabling LPM.
[    0.623265] usb usb4: New USB device found, idVendor=1d6b, idProduct=0003, bcdDevice= 6.00
[    0.623266] usb usb4: New USB device strings: Mfr=3, Product=2, SerialNumber=1
[    0.623267] usb usb4: Product: xHCI Host Controller
[    0.623268] usb usb4: Manufacturer: Linux 6.0.1-arch2-1 xhci-hcd
[    0.623268] usb usb4: SerialNumber: 0000:06:00.4
[    0.623312] hub 4-0:1.0: USB hub found
[    0.623317] hub 4-0:1.0: 2 ports detected
[    0.626448] nvme nvme0: pci function 0000:04:00.0
[    0.626467] nvme 0000:05:00.0: platform quirk: setting simple suspend
[    0.626486] nvme nvme1: pci function 0000:05:00.0
[    0.634757] nvme nvme0: missing or invalid SUBNQN field.
[    0.634778] nvme nvme0: Shutdown timeout set to 8 seconds
[    0.650146] nvme nvme1: allocated 64 MiB host memory buffer.
[    0.651167] nvme nvme0: 16/0/0 default/read/poll queues
[    0.654892]  nvme0n1: p1 p2 p3 p4
[    0.683316] nvme nvme1: 8/0/0 default/read/poll queues
[    0.686955]  nvme1n1: p1 p2 p3 p4
[    0.697887] input: AT Translated Set 2 keyboard as /devices/platform/i8042/serio0/input/input3
[    0.873782] usb 1-4: new high-speed USB device number 2 using xhci_hcd
[    0.874013] usb 3-2: new full-speed USB device number 2 using xhci_hcd
[    0.946835] EXT4-fs (nvme0n1p2): mounted filesystem with ordered data mode. Quota mode: none.
[    0.999617] systemd[1]: Successfully credited entropy passed from boot loader.
[    1.000452] systemd[1]: systemd 251.5-1-arch running in system mode (+PAM +AUDIT -SELINUX -APPARMOR -IMA +SMACK +SECCOMP +GCRYPT +GNUTLS +OPENSSL +ACL +BLKID +CURL +ELFUTILS +FIDO2 +IDN2 -IDN +IPTC +KMOD +LIBCRYPTSETUP +LIBFDISK +PCRE2 -PWQUALITY +P11KIT -QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD -BPF_FRAMEWORK +XKBCOMMON +UTMP -SYSVINIT default-hierarchy=unified)
[    1.000456] systemd[1]: Detected architecture x86-64.
[    1.001098] systemd[1]: Hostname set to <nomade007>.
[    1.037397] usb 1-4: New USB device found, idVendor=13d3, idProduct=56a2, bcdDevice=19.02
[    1.037400] usb 1-4: New USB device strings: Mfr=3, Product=1, SerialNumber=2
[    1.037401] usb 1-4: Product: USB2.0 HD UVC WebCam
[    1.037402] usb 1-4: Manufacturer: Azurewave
[    1.037403] usb 1-4: SerialNumber: 0x0001
[    1.039764] usb 3-2: New USB device found, idVendor=046d, idProduct=c534, bcdDevice=29.01
[    1.039767] usb 3-2: New USB device strings: Mfr=1, Product=2, SerialNumber=0
[    1.039768] usb 3-2: Product: USB Receiver
[    1.039769] usb 3-2: Manufacturer: Logitech
[    1.125774] systemd[1]: Queued start job for default target Graphical Interface.
[    1.156284] systemd[1]: Created slice Slice /system/getty.
[    1.156828] systemd[1]: Created slice Slice /system/modprobe.
[    1.157113] systemd[1]: Created slice Slice /system/systemd-fsck.
[    1.157383] systemd[1]: Created slice User and Session Slice.
[    1.157575] systemd[1]: Started Dispatch Password Requests to Console Directory Watch.
[    1.157802] systemd[1]: Started Forward Password Requests to Wall Directory Watch.
[    1.158080] systemd[1]: Set up automount Arbitrary Executable File Formats File System Automount Point.
[    1.158339] systemd[1]: Reached target Local Encrypted Volumes.
[    1.158495] systemd[1]: Reached target Login Prompts.
[    1.158625] systemd[1]: Reached target Local Integrity Protected Volumes.
[    1.158806] systemd[1]: Reached target Remote File Systems.
[    1.158948] systemd[1]: Reached target Slice Units.
[    1.159082] systemd[1]: Reached target Local Verity Protected Volumes.
[    1.159273] systemd[1]: Listening on Device-mapper event daemon FIFOs.
[    1.159506] systemd[1]: Listening on LVM2 poll daemon socket.
[    1.160290] systemd[1]: Listening on Process Core Dump Socket.
[    1.160513] systemd[1]: Listening on Journal Audit Socket.
[    1.160695] systemd[1]: Listening on Journal Socket (/dev/log).
[    1.160877] systemd[1]: Listening on Journal Socket.
[    1.161050] systemd[1]: Listening on Network Service Netlink Socket.
[    1.162016] systemd[1]: Listening on udev Control Socket.
[    1.162245] systemd[1]: Listening on udev Kernel Socket.
[    1.162883] systemd[1]: Mounting Huge Pages File System...
[    1.163370] systemd[1]: Mounting POSIX Message Queue File System...
[    1.163819] systemd[1]: Mounting Kernel Debug File System...
[    1.164274] systemd[1]: Mounting Kernel Trace File System...
[    1.164830] systemd[1]: Starting Create List of Static Device Nodes...
[    1.165289] systemd[1]: Starting Monitoring of LVM2 mirrors, snapshots etc. using dmeventd or progress polling...
[    1.165831] systemd[1]: Starting Load Kernel Module configfs...
[    1.166289] systemd[1]: Starting Load Kernel Module drm...
[    1.166736] systemd[1]: Starting Load Kernel Module fuse...
[    1.166865] systemd[1]: File System Check on Root Device was skipped because of a failed condition check (ConditionPathIsReadWrite=!/).
[    1.167546] systemd[1]: Starting Journal Service...
[    1.168251] systemd[1]: Starting Load Kernel Modules...
[    1.168708] systemd[1]: Starting Remount Root and Kernel File Systems...
[    1.168852] systemd[1]: Repartition Root Disk was skipped because all trigger condition checks failed.
[    1.169199] systemd[1]: Starting Coldplug All udev Devices...
[    1.169923] systemd[1]: Mounted Huge Pages File System.
[    1.170066] systemd[1]: Mounted POSIX Message Queue File System.
[    1.170210] systemd[1]: Mounted Kernel Debug File System.
[    1.170342] systemd[1]: Mounted Kernel Trace File System.
[    1.170525] systemd[1]: Finished Create List of Static Device Nodes.
[    1.170776] systemd[1]: modprobe@configfs.service: Deactivated successfully.
[    1.170833] systemd[1]: Finished Load Kernel Module configfs.
[    1.171045] systemd[1]: modprobe@drm.service: Deactivated successfully.
[    1.171098] systemd[1]: Finished Load Kernel Module drm.
[    1.171607] systemd[1]: Mounting Kernel Configuration File System...
[    1.171942] EXT4-fs (nvme0n1p2): re-mounted. Quota mode: none.
[    1.172451] systemd[1]: Finished Remount Root and Kernel File Systems.
[    1.172641] systemd[1]: Mounted Kernel Configuration File System.
[    1.172825] systemd[1]: First Boot Wizard was skipped because of a failed condition check (ConditionFirstBoot=yes).
[    1.173052] systemd[1]: Rebuild Hardware Database was skipped because of a failed condition check (ConditionNeedsUpdate=/etc).
[    1.173456] fuse: init (API version 7.36)
[    1.173500] systemd[1]: Starting Load/Save Random Seed...
[    1.173634] systemd[1]: Create System Users was skipped because of a failed condition check (ConditionNeedsUpdate=/etc).
[    1.174032] systemd[1]: Starting Create Static Device Nodes in /dev...
[    1.174331] systemd[1]: modprobe@fuse.service: Deactivated successfully.
[    1.174405] systemd[1]: Finished Load Kernel Module fuse.
[    1.174541] audit: type=1130 audit(1666913089.233:2): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=modprobe@fuse comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[    1.174546] audit: type=1131 audit(1666913089.233:3): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=modprobe@fuse comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[    1.174959] systemd[1]: Mounting FUSE Control File System...
[    1.175948] systemd[1]: Mounted FUSE Control File System.
[    1.182524] systemd[1]: Finished Load/Save Random Seed.
[    1.182651] audit: type=1130 audit(1666913089.239:4): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-random-seed comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[    1.182726] systemd[1]: First Boot Complete was skipped because of a failed condition check (ConditionFirstBoot=yes).
[    1.186358] device-mapper: uevent: version 1.0.3
[    1.186418] device-mapper: ioctl: 4.47.0-ioctl (2022-07-28) initialised: dm-devel@redhat.com
[    1.188994] systemd[1]: Finished Create Static Device Nodes in /dev.
[    1.190853] usb 3-3: new full-speed USB device number 3 using xhci_hcd
[    1.194449] audit: type=1130 audit(1666913089.253:5): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-tmpfiles-setup-dev comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[    1.194693] audit: type=1334 audit(1666913089.253:6): prog-id=9 op=LOAD
[    1.194712] audit: type=1334 audit(1666913089.253:7): prog-id=10 op=LOAD
[    1.194941] systemd[1]: Starting Rule-based Manager for Device Events and Files...
[    1.201457] systemd[1]: Started Journal Service.
[    1.205422] audit: type=1130 audit(1666913089.263:8): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-journald comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[    1.211380] systemd-journald[334]: Received client request to flush runtime journal.
[    1.235781] audit: type=1130 audit(1666913089.293:9): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-udevd comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[    1.261546] audit: type=1130 audit(1666913089.319:10): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=lvm2-monitor comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[    1.294216] input: Asus Wireless Radio Control as /devices/LNXSYSTM:00/LNXSYBUS:00/ATK4002:00/input/input4
[    1.298319] ACPI: video: Video Device [VGA] (multi-head: yes  rom: no  post: no)
[    1.298641] acpi device:10: registered as cooling_device17
[    1.298689] input: Video Bus as /devices/LNXSYSTM:00/LNXSYBUS:00/PNP0A08:00/device:0f/LNXVIDEO:01/input/input5
[    1.303576] acpi PNP0C14:01: duplicate WMI GUID 05901221-D566-11D1-B2F0-00A0C9062910 (first instance was on PNP0C14:00)
[    1.306114] piix4_smbus 0000:00:14.0: SMBus Host Controller at 0xb00, revision 0
[    1.306117] piix4_smbus 0000:00:14.0: Using register 0x02 for SMBus port selection
[    1.306170] piix4_smbus 0000:00:14.0: Auxiliary SMBus Host Controller at 0xb20
[    1.308307] ccp 0000:06:00.2: enabling device (0000 -> 0002)
[    1.308450] ccp 0000:06:00.2: ccp: unable to access the device: you might be running a broken BIOS.
[    1.313022] input: PC Speaker as /devices/platform/pcspkr/input/input6
[    1.318590] ccp 0000:06:00.2: tee enabled
[    1.318595] ccp 0000:06:00.2: psp enabled
[    1.365815] usb 3-3: New USB device found, idVendor=8087, idProduct=0029, bcdDevice= 0.01
[    1.365819] usb 3-3: New USB device strings: Mfr=0, Product=0, SerialNumber=0
[    1.388294] mc: Linux media interface: v0.10
[    1.405684] RAPL PMU: API unit is 2^-32 Joules, 1 fixed counters, 163840 ms ovfl timer
[    1.405685] RAPL PMU: hw unit of domain package 2^-16 Joules
[    1.421923] tsc: Refined TSC clocksource calibration: 3193.987 MHz
[    1.421930] clocksource: tsc: mask: 0xffffffffffffffff max_cycles: 0x2e0a19f15f2, max_idle_ns: 440795287071 ns
[    1.421954] clocksource: Switched to clocksource tsc
[    1.444810] Adding 16777212k swap on /dev/nvme0n1p3.  Priority:-2 extents:1 across:16777212k SSFS
[    1.503435] cryptd: max_cpu_qlen set to 1000
[    1.509267] EXT4-fs (nvme0n1p4): mounted filesystem with ordered data mode. Quota mode: none.
[    1.586202] input: ELAN1203:00 04F3:307A Mouse as /devices/platform/AMDI0010:03/i2c-0/i2c-ELAN1203:00/0018:04F3:307A.0001/input/input7
[    1.586269] input: ELAN1203:00 04F3:307A Touchpad as /devices/platform/AMDI0010:03/i2c-0/i2c-ELAN1203:00/0018:04F3:307A.0001/input/input8
[    1.586397] hid-generic 0018:04F3:307A.0001: input,hidraw0: I2C HID v1.00 Mouse [ELAN1203:00 04F3:307A] on i2c-ELAN1203:00
[    1.598189] AVX2 version of gcm_enc/dec engaged.
[    1.598219] AES CTR mode by8 optimization enabled
[    1.612676] sp5100_tco: SP5100/SB800 TCO WatchDog Timer Driver
[    1.612776] sp5100-tco sp5100-tco: Using 0xfeb00000 for watchdog MMIO address
[    1.617652] videodev: Linux video capture interface: v2.00
[    1.618015] sp5100-tco sp5100-tco: initialized. heartbeat=60 sec (nowayout=0)
[    1.665345] snd_rn_pci_acp3x 0000:06:00.5: enabling device (0000 -> 0002)
[    1.699947] cfg80211: Loading compiled-in X.509 certificates for regulatory database
[    1.700169] cfg80211: Loaded X.509 cert 'sforshee: 00b28ddf47aef9cea7'
[    1.707772] platform regulatory.0: Direct firmware load for regulatory.db failed with error -2
[    1.707778] cfg80211: failed to load regulatory.db
[    1.707821] input: Logitech USB Receiver as /devices/pci0000:00/0000:00:08.1/0000:06:00.4/usb3/3-2/3-2:1.0/0003:046D:C534.0002/input/input9
[    1.717871] r8169 0000:02:00.0 eth0: RTL8168h/8111h, f0:2f:74:a1:38:80, XID 541, IRQ 90
[    1.717876] r8169 0000:02:00.0 eth0: jumbo features [frames: 9194 bytes, tx checksumming: ko]
[    1.738493] Intel(R) Wireless WiFi driver for Linux
[    1.738549] iwlwifi 0000:03:00.0: enabling device (0000 -> 0002)
[    1.754543] iwlwifi 0000:03:00.0: Direct firmware load for iwlwifi-cc-a0-72.ucode failed with error -2
[    1.761603] hid-generic 0003:046D:C534.0002: input,hidraw1: USB HID v1.11 Keyboard [Logitech USB Receiver] on usb-0000:06:00.4-2/input0
[    1.769451] input: Logitech USB Receiver Mouse as /devices/pci0000:00/0000:00:08.1/0000:06:00.4/usb3/3-2/3-2:1.1/0003:046D:C534.0003/input/input10
[    1.769951] input: Logitech USB Receiver Consumer Control as /devices/pci0000:00/0000:00:08.1/0000:06:00.4/usb3/3-2/3-2:1.1/0003:046D:C534.0003/input/input11
[    1.790968] iwlwifi 0000:03:00.0: api flags index 2 larger than supported by driver
[    1.790979] iwlwifi 0000:03:00.0: TLV_FW_FSEQ_VERSION: FSEQ Version: 89.3.35.37
[    1.791161] iwlwifi 0000:03:00.0: loaded firmware version 71.058653f6.0 cc-a0-71.ucode op_mode iwlmvm
[    1.824865] input: Logitech USB Receiver System Control as /devices/pci0000:00/0000:00:08.1/0000:06:00.4/usb3/3-2/3-2:1.1/0003:046D:C534.0003/input/input12
[    1.824962] hid-generic 0003:046D:C534.0003: input,hiddev96,hidraw2: USB HID v1.11 Mouse [Logitech USB Receiver] on usb-0000:06:00.4-2/input1
[    1.825000] usbcore: registered new interface driver usbhid
[    1.825001] usbhid: USB HID core driver
[    1.828927] usb 1-4: Found UVC 1.00 device USB2.0 HD UVC WebCam (13d3:56a2)
[    1.835840] input: USB2.0 HD UVC WebCam: USB2.0 HD as /devices/pci0000:00/0000:00:08.1/0000:06:00.3/usb1/1-4/1-4:1.0/input/input15
[    1.835918] usbcore: registered new interface driver uvcvideo
[    1.913799] r8169 0000:02:00.0 enp2s0: renamed from eth0
[    2.157253] nvidia: loading out-of-tree module taints kernel.
[    2.157262] nvidia: module license 'NVIDIA' taints kernel.
[    2.157263] Disabling lock debugging due to kernel taint
[    2.172767] nvidia: module verification failed: signature and/or required key missing - tainting kernel
[    2.728070] ucsi_acpi USBC000:00: PPM init failed (-110)
[    2.742466] [drm] amdgpu kernel modesetting enabled.
[    2.745334] amdgpu: Virtual CRAT table created for CPU
[    2.745345] amdgpu: Topology: Add CPU node
[    2.745503] Console: switching to colour dummy device 80x25
[    2.745548] amdgpu 0000:06:00.0: vgaarb: deactivate vga console
[    2.745594] amdgpu 0000:06:00.0: enabling device (0006 -> 0007)
[    2.745635] [drm] initializing kernel modesetting (RENOIR 0x1002:0x1638 0x1043:0x16A2 0xC5).
[    2.745711] [drm] register mmio base: 0xFC500000
[    2.745712] [drm] register mmio size: 524288
[    2.747038] [drm] add ip block number 0 <soc15_common>
[    2.747040] [drm] add ip block number 1 <gmc_v9_0>
[    2.747041] [drm] add ip block number 2 <vega10_ih>
[    2.747041] [drm] add ip block number 3 <psp>
[    2.747043] [drm] add ip block number 4 <smu>
[    2.747044] [drm] add ip block number 5 <dm>
[    2.747045] [drm] add ip block number 6 <gfx_v9_0>
[    2.747046] [drm] add ip block number 7 <sdma_v4_0>
[    2.747047] [drm] add ip block number 8 <vcn_v2_0>
[    2.747048] [drm] add ip block number 9 <jpeg_v2_0>
[    2.747065] amdgpu 0000:06:00.0: amdgpu: Fetched VBIOS from VFCT
[    2.747067] amdgpu: ATOM BIOS: 113-CEZANNE-018
[    2.755690] [drm] VCN decode is enabled in VM mode
[    2.755691] [drm] VCN encode is enabled in VM mode
[    2.755692] [drm] JPEG decode is enabled in VM mode
[    2.755693] amdgpu 0000:06:00.0: amdgpu: Trusted Memory Zone (TMZ) feature enabled
[    2.755696] amdgpu 0000:06:00.0: amdgpu: PCIE atomic ops is not supported
[    2.755706] amdgpu 0000:06:00.0: amdgpu: MODE2 reset
[    2.755854] [drm] vm size is 262144 GB, 4 levels, block size is 9-bit, fragment size is 9-bit
[    2.755858] amdgpu 0000:06:00.0: amdgpu: VRAM: 512M 0x000000F400000000 - 0x000000F41FFFFFFF (512M used)
[    2.755860] amdgpu 0000:06:00.0: amdgpu: GART: 1024M 0x0000000000000000 - 0x000000003FFFFFFF
[    2.755861] amdgpu 0000:06:00.0: amdgpu: AGP: 267419648M 0x000000F800000000 - 0x0000FFFFFFFFFFFF
[    2.755865] [drm] Detected VRAM RAM=512M, BAR=512M
[    2.755866] [drm] RAM width 128bits DDR4
[    2.755901] [drm] amdgpu: 512M of VRAM memory ready
[    2.755902] [drm] amdgpu: 31854M of GTT memory ready.
[    2.755909] [drm] GART: num cpu pages 262144, num gpu pages 262144
[    2.756026] [drm] PCIE GART of 1024M enabled.
[    2.756028] [drm] PTB located at 0x000000F400A00000
[    2.760693] amdgpu 0000:06:00.0: amdgpu: PSP runtime database doesn't exist
[    2.760696] amdgpu 0000:06:00.0: amdgpu: PSP runtime database doesn't exist
[    2.765080] [drm] Loading DMUB firmware via PSP: version=0x0101001F
[    2.787720] [drm] Found VCN firmware Version ENC: 1.17 DEC: 5 VEP: 0 Revision: 2
[    2.787728] amdgpu 0000:06:00.0: amdgpu: Will use PSP to load VCN firmware
[    2.798720] snd_hda_intel 0000:06:00.1: enabling device (0000 -> 0002)
[    2.798902] snd_hda_intel 0000:06:00.1: Handle vga_switcheroo audio client
[    2.799148] snd_hda_intel 0000:06:00.6: enabling device (0000 -> 0002)
[    2.800469] nvidia-nvlink: Nvlink Core is being initialized, major device number 510

[    2.801461] SVM: TSC scaling supported
[    2.801469] kvm: Nested Virtualization enabled
[    2.801471] SVM: kvm: Nested Paging enabled
[    2.801490] SVM: Virtual VMLOAD VMSAVE supported
[    2.801491] SVM: Virtual GIF supported
[    2.801492] SVM: LBR virtualization supported
[    2.801529] NVRM: No NVIDIA GPU found.
[    2.801741] nvidia-nvlink: Unregistered Nvlink Core, major device number 510
[    2.824116] asus_wmi: ASUS WMI generic driver loaded
[    2.824858] Bluetooth: Core ver 2.22
[    2.824874] NET: Registered PF_BLUETOOTH protocol family
[    2.824875] Bluetooth: HCI device and connection manager initialized
[    2.824880] Bluetooth: HCI socket layer initialized
[    2.824881] Bluetooth: L2CAP socket layer initialized
[    2.824884] Bluetooth: SCO socket layer initialized
[    2.828059] MCE: In-kernel MCE decoding enabled.
[    2.828226] asus_wmi: Initialization: 0x1
[    2.828351] asus_wmi: SFUN value: 0x21
[    2.828354] asus-nb-wmi asus-nb-wmi: Detected ATK, not ASUSWMI, use DSTS
[    2.828356] asus-nb-wmi asus-nb-wmi: Detected ATK, enable event queue
[    2.828375] input: HD-Audio Generic HDMI/DP,pcm=3 as /devices/pci0000:00/0000:00:08.1/0000:06:00.1/sound/card0/input16
[    2.834584] iwlwifi 0000:03:00.0: Detected Intel(R) Wi-Fi 6 AX200 160MHz, REV=0x340
[    2.834630] thermal thermal_zone1: failed to read out thermal zone (-61)
[    2.835062] asus-nb-wmi asus-nb-wmi: Using throttle_thermal_policy for platform_profile support
[    2.836389] snd_hda_codec_realtek hdaudioC1D0: autoconfig for ALC256: line_outs=1 (0x14/0x0/0x0/0x0/0x0) type:speaker
[    2.836392] snd_hda_codec_realtek hdaudioC1D0:    speaker_outs=0 (0x0/0x0/0x0/0x0/0x0)
[    2.836393] snd_hda_codec_realtek hdaudioC1D0:    hp_outs=1 (0x21/0x0/0x0/0x0/0x0)
[    2.836394] snd_hda_codec_realtek hdaudioC1D0:    mono: mono_out=0x0
[    2.836394] snd_hda_codec_realtek hdaudioC1D0:    inputs:
[    2.836395] snd_hda_codec_realtek hdaudioC1D0:      Headset Mic=0x19
[    2.836396] snd_hda_codec_realtek hdaudioC1D0:      Internal Mic=0x12
[    2.836934] input: Asus WMI hotkeys as /devices/platform/asus-nb-wmi/input/input17
[    2.948735] input: HD-Audio Generic Headphone as /devices/pci0000:00/0000:00:08.1/0000:06:00.6/sound/card1/input18
[    2.952561] intel_rapl_common: Found RAPL domain package
[    2.952563] intel_rapl_common: Found RAPL domain core
[    2.953860] Asymmetric key parser 'pkcs8' registered
[    2.961260] iwlwifi 0000:03:00.0: Detected RF HR B3, rfid=0x10a100
[    2.964618] usbcore: registered new interface driver btusb
[    2.964631] vboxdrv: Found 16 processor cores
[    2.965812] Bluetooth: hci0: Bootloader revision 0.3 build 0 week 24 2017
[    2.967817] Bluetooth: hci0: Device revision is 1
[    2.967818] Bluetooth: hci0: Secure boot is enabled
[    2.967819] Bluetooth: hci0: OTP lock is enabled
[    2.967820] Bluetooth: hci0: API lock is enabled
[    2.967820] Bluetooth: hci0: Debug lock is disabled
[    2.967821] Bluetooth: hci0: Minimum firmware build 1 week 10 2014
[    2.988788] vboxdrv: TSC mode is Invariant, tentative frequency 3193978781 Hz
[    2.988790] vboxdrv: Successfully loaded version 6.1.38 r153438 (interface 0x00320000)
[    2.992605] Bluetooth: hci0: Found device firmware: intel/ibt-20-1-3.sfi
[    2.992623] Bluetooth: hci0: Boot Address: 0x24800
[    2.992624] Bluetooth: hci0: Firmware Version: 20-28.22
[    3.026811] iwlwifi 0000:03:00.0: base HW address: b0:a4:60:e9:86:8a
[    3.042160] logitech-djreceiver 0003:046D:C534.0002: hidraw1: USB HID v1.11 Keyboard [Logitech USB Receiver] on usb-0000:06:00.4-2/input0
[    3.068934] asus_wmi: fan_curve_get_factory_default (0x00110024) failed: -61
[    3.069138] asus_wmi: fan_curve_get_factory_default (0x00110025) failed: -61
[    3.073049] ACPI: battery: new extension: ASUS Battery Extension
[    3.095453] VBoxNetAdp: Successfully started.
[    3.097066] VBoxNetFlt: Successfully started.
[    3.101164] Guest personality initialized and is inactive
[    3.101178] VMCI host device registered (name=vmci, major=10, minor=121)
[    3.101179] Initialized host personality
[    3.111273] input: ELAN1203:00 04F3:307A Mouse as /devices/platform/AMDI0010:03/i2c-0/i2c-ELAN1203:00/0018:04F3:307A.0001/input/input19
[    3.131510] input: ELAN1203:00 04F3:307A Touchpad as /devices/platform/AMDI0010:03/i2c-0/i2c-ELAN1203:00/0018:04F3:307A.0001/input/input20
[    3.228190] hid-multitouch 0018:04F3:307A.0001: input,hidraw0: I2C HID v1.00 Mouse [ELAN1203:00 04F3:307A] on i2c-ELAN1203:00
[    3.228940] NET: Registered PF_ALG protocol family
[    3.229041] Bluetooth: BNEP (Ethernet Emulation) ver 1.3
[    3.229043] Bluetooth: BNEP filters: protocol multicast
[    3.229046] Bluetooth: BNEP socket layer initialized
[    3.334843] mousedev: PS/2 mouse device common for all mice
[    3.334971] logitech-djreceiver 0003:046D:C534.0003: hiddev96,hidraw2: USB HID v1.11 Mouse [Logitech USB Receiver] on usb-0000:06:00.4-2/input1
[    3.371411] Generic FE-GE Realtek PHY r8169-0-200:00: attached PHY driver (mii_bus:phy_addr=r8169-0-200:00, irq=MAC)
[    3.392801] logitech-djreceiver 0003:046D:C534.0003: device of type eQUAD nano Lite (0x0a) connected on slot 1
[    3.393073] input: Logitech Wireless Keyboard PID:4023 Keyboard as /devices/pci0000:00/0000:00:08.1/0000:06:00.4/usb3/3-2/3-2:1.1/0003:046D:C534.0003/0003:046D:4023.0004/input/input21
[    3.393291] hid-generic 0003:046D:4023.0004: input,hidraw3: USB HID v1.11 Keyboard [Logitech Wireless Keyboard PID:4023] on usb-0000:06:00.4-2/input1:1
[    3.394795] logitech-djreceiver 0003:046D:C534.0003: device of type eQUAD nano Lite (0x0a) connected on slot 2
[    3.394925] input: Logitech Wireless Mouse PID:4058 Mouse as /devices/pci0000:00/0000:00:08.1/0000:06:00.4/usb3/3-2/3-2:1.1/0003:046D:C534.0003/0003:046D:4058.0005/input/input26
[    3.395010] hid-generic 0003:046D:4058.0005: input,hidraw4: USB HID v1.11 Mouse [Logitech Wireless Mouse PID:4058] on usb-0000:06:00.4-2/input1:2
[    3.515440] [drm] reserve 0x400000 from 0xf41f800000 for PSP TMR
[    3.574915] r8169 0000:02:00.0 enp2s0: Link is Down
[    3.597916] amdgpu 0000:06:00.0: amdgpu: RAS: optional ras ta ucode is not available
[    3.606485] amdgpu 0000:06:00.0: amdgpu: RAP: optional rap ta ucode is not available
[    3.606487] amdgpu 0000:06:00.0: amdgpu: SECUREDISPLAY: securedisplay ta ucode is not available
[    3.609501] amdgpu 0000:06:00.0: amdgpu: SMU is initialized successfully!
[    3.610567] [drm] Display Core initialized with v3.2.198!
[    3.611093] [drm] DMUB hardware initialized: version=0x0101001F
[    3.623272] snd_hda_intel 0000:06:00.1: bound 0000:06:00.0 (ops amdgpu_dm_audio_component_bind_ops [amdgpu])
[    3.760106] [drm] kiq ring mec 2 pipe 1 q 0
[    3.764738] [drm] VCN decode and encode initialized successfully(under DPG Mode).
[    3.764755] [drm] JPEG decode initialized successfully.
[    3.765746] kfd kfd: amdgpu: Allocated 3969056 bytes on gart
[    3.765793] amdgpu: sdma_bitmap: 3
[    3.813235] memmap_init_zone_device initialised 131072 pages in 0ms
[    3.813238] amdgpu: HMM registered 512MB device memory
[    3.813254] amdgpu: SRAT table not found
[    3.813254] amdgpu: Virtual CRAT table created for GPU
[    3.813714] amdgpu: Topology: Add dGPU node [0x1638:0x1002]
[    3.813719] kfd kfd: amdgpu: added device 1002:1638
[    3.813750] amdgpu 0000:06:00.0: amdgpu: SE 1, SH per SE 1, CU per SH 8, active_cu_number 8
[    3.813819] amdgpu 0000:06:00.0: amdgpu: ring gfx uses VM inv eng 0 on hub 0
[    3.813821] amdgpu 0000:06:00.0: amdgpu: ring comp_1.0.0 uses VM inv eng 1 on hub 0
[    3.813823] amdgpu 0000:06:00.0: amdgpu: ring comp_1.1.0 uses VM inv eng 4 on hub 0
[    3.813824] amdgpu 0000:06:00.0: amdgpu: ring comp_1.2.0 uses VM inv eng 5 on hub 0
[    3.813825] amdgpu 0000:06:00.0: amdgpu: ring comp_1.3.0 uses VM inv eng 6 on hub 0
[    3.813827] amdgpu 0000:06:00.0: amdgpu: ring comp_1.0.1 uses VM inv eng 7 on hub 0
[    3.813828] amdgpu 0000:06:00.0: amdgpu: ring comp_1.1.1 uses VM inv eng 8 on hub 0
[    3.813829] amdgpu 0000:06:00.0: amdgpu: ring comp_1.2.1 uses VM inv eng 9 on hub 0
[    3.813830] amdgpu 0000:06:00.0: amdgpu: ring comp_1.3.1 uses VM inv eng 10 on hub 0
[    3.813831] amdgpu 0000:06:00.0: amdgpu: ring kiq_2.1.0 uses VM inv eng 11 on hub 0
[    3.813832] amdgpu 0000:06:00.0: amdgpu: ring sdma0 uses VM inv eng 0 on hub 1
[    3.813834] amdgpu 0000:06:00.0: amdgpu: ring vcn_dec uses VM inv eng 1 on hub 1
[    3.813835] amdgpu 0000:06:00.0: amdgpu: ring vcn_enc0 uses VM inv eng 4 on hub 1
[    3.813836] amdgpu 0000:06:00.0: amdgpu: ring vcn_enc1 uses VM inv eng 5 on hub 1
[    3.813838] amdgpu 0000:06:00.0: amdgpu: ring jpeg_dec uses VM inv eng 6 on hub 1
[    3.814971] [drm] Initialized amdgpu 3.48.0 20150101 for 0000:06:00.0 on minor 0
[    3.822346] fbcon: amdgpudrmfb (fb0) is primary device
[    3.822381] [drm] DSC precompute is not needed.
[    3.900940] Console: switching to colour frame buffer device 240x67
[    3.935162] amdgpu 0000:06:00.0: [drm] fb0: amdgpudrmfb frame buffer device
[    4.081114] logitech-hidpp-device 0003:046D:4023.0004: HID++ 2.0 device connected.
[    4.344176] Bluetooth: hci0: Waiting for firmware download to complete
[    4.344803] Bluetooth: hci0: Firmware loaded in 1320504 usecs
[    4.344829] Bluetooth: hci0: Waiting for device to boot
[    4.360807] Bluetooth: hci0: Device booted in 15612 usecs
[    4.360811] Bluetooth: hci0: Malformed MSFT vendor event: 0x02
[    4.361695] Bluetooth: hci0: Found Intel DDC parameters: intel/ibt-20-1-3.ddc
[    4.366808] Bluetooth: hci0: Applying Intel DDC parameters completed
[    4.369811] Bluetooth: hci0: Firmware revision 0.3 build 20 week 28 2022
[    4.516889] Bluetooth: MGMT ver 1.22
[    4.923213] pcieport 0000:00:01.1: pciehp: Slot(0): Card present
[    4.923219] pcieport 0000:00:01.1: pciehp: Slot(0): Link Up
[    4.945165] wlan0: authenticate with 6a:02:71:a7:d6:fd
[    4.988368] wlan0: bad VHT capabilities, disabling VHT
[    4.988381] wlan0: Invalid HE elem, Disable HE
[    4.988383] wlan0: 80 MHz not supported, disabling VHT
[    4.997046] wlan0: send auth to 6a:02:71:a7:d6:fd (try 1/3)
[    5.004014] wlan0: authenticate with 6a:02:71:a7:d6:fd
[    5.055008] wlan0: send auth to 6a:02:71:a7:d6:fd (try 1/3)
[    5.055057] pci 0000:01:00.0: [10de:2520] type 00 class 0x030000
[    5.055094] pci 0000:01:00.0: reg 0x10: [mem 0x00000000-0x00ffffff]
[    5.055109] pci 0000:01:00.0: reg 0x14: [mem 0x00000000-0x1ffffffff 64bit pref]
[    5.055121] pci 0000:01:00.0: reg 0x1c: [mem 0x00000000-0x01ffffff 64bit pref]
[    5.055129] pci 0000:01:00.0: reg 0x24: [io  0x0000-0x007f]
[    5.055136] pci 0000:01:00.0: reg 0x30: [mem 0x00000000-0x0007ffff pref]
[    5.055145] pci 0000:01:00.0: Max Payload Size set to 256 (was 128, max 256)
[    5.055257] pci 0000:01:00.0: PME# supported from D0 D3hot
[    5.055359] pci 0000:01:00.0: 63.008 Gb/s available PCIe bandwidth, limited by 8.0 GT/s PCIe x8 link at 0000:00:01.1 (capable of 252.048 Gb/s with 16.0 GT/s PCIe x16 link)
[    5.056064] pci 0000:01:00.0: vgaarb: bridge control possible
[    5.056068] pci 0000:01:00.0: vgaarb: VGA device added: decodes=io+mem,owns=none,locks=none
[    5.056104] pci 0000:01:00.0: Adding to iommu group 14
[    5.056317] pci 0000:01:00.1: [10de:228e] type 00 class 0x040300
[    5.056329] pci 0000:01:00.1: reg 0x10: [mem 0x00000000-0x00003fff]
[    5.056353] pci 0000:01:00.1: Max Payload Size set to 256 (was 128, max 256)
[    5.056488] pci 0000:01:00.1: Adding to iommu group 14
[    5.056522] pci 0000:01:00.0: BAR 1: assigned [mem 0xfc00000000-0xfdffffffff 64bit pref]
[    5.056528] pci 0000:01:00.0: BAR 3: assigned [mem 0xfe00000000-0xfe01ffffff 64bit pref]
[    5.056534] pci 0000:01:00.0: BAR 0: assigned [mem 0xfb000000-0xfbffffff]
[    5.056536] pci 0000:01:00.0: BAR 6: assigned [mem 0xfc000000-0xfc07ffff pref]
[    5.056537] pci 0000:01:00.1: BAR 0: assigned [mem 0xfc080000-0xfc083fff]
[    5.056540] pci 0000:01:00.0: BAR 5: assigned [io  0xf000-0xf07f]
[    5.056542] pcieport 0000:00:01.1: PCI bridge to [bus 01]
[    5.056543] pcieport 0000:00:01.1:   bridge window [io  0xf000-0xffff]
[    5.056547] pcieport 0000:00:01.1:   bridge window [mem 0xfb000000-0xfc0fffff]
[    5.056549] pcieport 0000:00:01.1:   bridge window [mem 0xfc00000000-0xfe01ffffff 64bit pref]
[    5.056626] pci 0000:01:00.1: D0 power state depends on 0000:01:00.0
[    5.056648] snd_hda_intel 0000:01:00.1: enabling device (0000 -> 0002)
[    5.056736] snd_hda_intel 0000:01:00.1: Disabling MSI
[    5.056738] snd_hda_intel 0000:01:00.1: Handle vga_switcheroo audio client
[    5.057090] wlan0: authenticated
[    5.065097] input: HDA NVidia HDMI/DP,pcm=3 as /devices/pci0000:00/0000:00:01.1/0000:01:00.1/sound/card2/input30
[    5.065120] input: HDA NVidia HDMI/DP,pcm=7 as /devices/pci0000:00/0000:00:01.1/0000:01:00.1/sound/card2/input31
[    5.065139] input: HDA NVidia HDMI/DP,pcm=8 as /devices/pci0000:00/0000:00:01.1/0000:01:00.1/sound/card2/input32
[    5.065156] input: HDA NVidia HDMI/DP,pcm=9 as /devices/pci0000:00/0000:00:01.1/0000:01:00.1/sound/card2/input33
[    5.085167] wlan0: associate with 6a:02:71:a7:d6:fd (try 1/3)
[    5.088846] wlan0: RX AssocResp from 6a:02:71:a7:d6:fd (capab=0x411 status=0 aid=3)
[    5.097236] wlan0: associated
[    5.213626] IPv6: ADDRCONF(NETDEV_CHANGE): wlan0: link becomes ready
[    5.434457] kauditd_printk_skb: 57 callbacks suppressed
[    5.434460] audit: type=1334 audit(1666913093.490:64): prog-id=22 op=LOAD
[    5.434513] audit: type=1334 audit(1666913093.490:65): prog-id=23 op=LOAD
[    5.434530] audit: type=1334 audit(1666913093.490:66): prog-id=24 op=LOAD
[    5.497345] audit: type=1130 audit(1666913093.553:67): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-localed comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[    5.531230] audit: type=1334 audit(1666913093.586:68): prog-id=25 op=LOAD
[    5.531242] audit: type=1334 audit(1666913093.586:69): prog-id=26 op=LOAD
[    5.574627] audit: type=1130 audit(1666913093.630:70): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=rtkit-daemon comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[    5.583015] audit: type=1130 audit(1666913093.640:71): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=power-profiles-daemon comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[    5.583118] audit: type=1130 audit(1666913093.640:72): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=geoclue comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[    5.594938] input: Logitech Wireless Keyboard PID:4023 as /devices/pci0000:00/0000:00:08.1/0000:06:00.4/usb3/3-2/3-2:1.1/0003:046D:C534.0003/0003:046D:4023.0004/input/input34
[    5.595056] logitech-hidpp-device 0003:046D:4023.0004: input,hidraw3: USB HID v1.11 Keyboard [Logitech Wireless Keyboard PID:4023] on usb-0000:06:00.4-2/input1:1
[    5.660872] input: Logitech Wireless Mouse as /devices/pci0000:00/0000:00:08.1/0000:06:00.4/usb3/3-2/3-2:1.1/0003:046D:C534.0003/0003:046D:4058.0005/input/input35
[    5.661089] logitech-hidpp-device 0003:046D:4058.0005: input,hidraw4: USB HID v1.11 Mouse [Logitech Wireless Mouse] on usb-0000:06:00.4-2/input1:2
[    5.671502] audit: type=1130 audit(1666913093.730:73): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=upower comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[    5.767737] rfkill: input handler disabled
[    6.109965] nvidia-nvlink: Nvlink Core is being initialized, major device number 510

[    6.110522] nvidia 0000:01:00.0: enabling device (0000 -> 0003)
[    6.110603] nvidia 0000:01:00.0: vgaarb: changed VGA decodes: olddecodes=io+mem,decodes=none:owns=none
[    6.156217] NVRM: loading NVIDIA UNIX x86_64 Kernel Module  520.56.06  Thu Oct  6 21:38:55 UTC 2022
[    6.199224] ACPI Warning: \_SB.NPCF._DSM: Argument #4 type mismatch - Found [Buffer], ACPI requires [Package] (20220331/nsarguments-61)
[    6.199280] ACPI Warning: \_SB.PCI0.GPP0.PEGP._DSM: Argument #4 type mismatch - Found [Buffer], ACPI requires [Package] (20220331/nsarguments-61)
[    7.133271] nvidia-modeset: Loading NVIDIA Kernel Mode Setting Driver for UNIX platforms  520.56.06  Thu Oct  6 21:22:53 UTC 2022
[    7.138577] [drm] [nvidia-drm] [GPU ID 0x00000100] Loading driver
[    7.138579] [drm] Initialized nvidia-drm 0.0.0 20160202 for 0000:01:00.0 on minor 1
[    9.805268] rfkill: input handler enabled
[   10.245081] logitech-hidpp-device 0003:046D:4058.0005: HID++ 4.5 device connected.
[   10.960782] kauditd_printk_skb: 16 callbacks suppressed
[   10.960785] audit: type=1130 audit(1666913099.016:86): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=udisks2 comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[   11.377117] rfkill: input handler disabled
[   11.452895] Bluetooth: RFCOMM TTY layer initialized
[   11.452901] Bluetooth: RFCOMM socket layer initialized
[   11.452904] Bluetooth: RFCOMM ver 1.11
[   13.149326] audit: type=1106 audit(1666913101.206:87): pid=737 uid=0 auid=120 ses=1 msg='op=PAM:session_close grantors=pam_loginuid,pam_keyinit,pam_succeed_if,pam_permit,pam_systemd,pam_env acct="gdm" exe="/usr/lib/gdm-session-worker" hostname=nomade007 addr=? terminal=/dev/tty1 res=success'
[   13.149370] audit: type=1104 audit(1666913101.206:88): pid=737 uid=0 auid=120 ses=1 msg='op=PAM:setcred grantors=pam_permit acct="gdm" exe="/usr/lib/gdm-session-worker" hostname=nomade007 addr=? terminal=/dev/tty1 res=success'
[   13.764994] audit: type=1131 audit(1666913101.823:89): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=NetworkManager-dispatcher comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[   23.178893] audit: type=1131 audit(1666913111.360:90): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=user@120 comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[   23.211534] audit: type=1131 audit(1666913111.394:91): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=user-runtime-dir@120 comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[   41.730798] audit: type=1131 audit(1666913129.988:92): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-hostnamed comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[   41.826780] audit: type=1334 audit(1666913130.085:93): prog-id=0 op=UNLOAD
[   41.826792] audit: type=1334 audit(1666913130.085:94): prog-id=0 op=UNLOAD
[   41.826797] audit: type=1334 audit(1666913130.085:95): prog-id=0 op=UNLOAD
[   43.559396] audit: type=1131 audit(1666913131.817:96): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-localed comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[   43.674606] audit: type=1334 audit(1666913131.933:97): prog-id=0 op=UNLOAD
[   43.674622] audit: type=1334 audit(1666913131.933:98): prog-id=0 op=UNLOAD
[   43.674629] audit: type=1334 audit(1666913131.933:99): prog-id=0 op=UNLOAD
[   54.796543] wlan0: deauthenticating from 6a:02:71:a7:d6:fd by local choice (Reason: 3=DEAUTH_LEAVING)
[   55.029407] audit: type=1130 audit(1666913143.293:100): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=NetworkManager-dispatcher comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[   57.400521] wlan0: authenticate with 6a:02:71:a7:d6:fd
[   57.423088] wlan0: bad VHT capabilities, disabling VHT
[   57.423091] wlan0: Invalid HE elem, Disable HE
[   57.423092] wlan0: 80 MHz not supported, disabling VHT
[   57.425779] wlan0: send auth to 6a:02:71:a7:d6:fd (try 1/3)
[   57.453752] wlan0: authenticated
[   57.497782] wlan0: associate with 6a:02:71:a7:d6:fd (try 1/3)
[   57.529767] wlan0: RX AssocResp from 6a:02:71:a7:d6:fd (capab=0x411 status=0 aid=3)
[   57.541825] wlan0: associated
[   57.596475] IPv6: ADDRCONF(NETDEV_CHANGE): wlan0: link becomes ready
[   65.030655] audit: type=1131 audit(1666913153.302:101): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=NetworkManager-dispatcher comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[   65.790152] audit: type=1131 audit(1666913154.062:102): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=geoclue comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[   69.852109] wlan0: disconnect from AP 6a:02:71:a7:d6:fd for new auth to 8a:02:71:a7:d6:fd
[   69.914010] wlan0: authenticate with 8a:02:71:a7:d6:fd
[   69.960271] wlan0: Invalid HE elem, Disable HE
[   69.970050] wlan0: send auth to 8a:02:71:a7:d6:fd (try 1/3)
[   69.999565] wlan0: authenticated
[   70.055467] wlan0: associate with 8a:02:71:a7:d6:fd (try 1/3)
[   70.070179] wlan0: RX AssocResp from 8a:02:71:a7:d6:fd (capab=0x11 status=0 aid=2)
[   70.073064] wlan0: associated
[   70.074619] wlan0: deauthenticating from 8a:02:71:a7:d6:fd by local choice (Reason: 2=PREV_AUTH_NOT_VALID)
[   75.584833] wlan0: authenticate with 6a:02:71:a7:d6:fd
[   75.613820] wlan0: bad VHT capabilities, disabling VHT
[   75.613831] wlan0: Invalid HE elem, Disable HE
[   75.613834] wlan0: 80 MHz not supported, disabling VHT
[   75.617389] wlan0: send auth to 6a:02:71:a7:d6:fd (try 1/3)
[   75.645024] wlan0: authenticated
[   75.676176] wlan0: associate with 6a:02:71:a7:d6:fd (try 1/3)
[   75.690708] wlan0: RX AssocResp from 6a:02:71:a7:d6:fd (capab=0x411 status=0 aid=3)
[   75.702988] wlan0: associated
[   82.793662] wlan0: disconnect from AP 6a:02:71:a7:d6:fd for new auth to 8a:02:71:a7:d6:fd
[   82.843622] wlan0: authenticate with 8a:02:71:a7:d6:fd
[   82.883437] wlan0: Invalid HE elem, Disable HE
[   82.893272] wlan0: send auth to 8a:02:71:a7:d6:fd (try 1/3)
[   82.922574] wlan0: authenticated
[   82.945764] wlan0: associate with 8a:02:71:a7:d6:fd (try 1/3)
[   82.969973] wlan0: RX AssocResp from 8a:02:71:a7:d6:fd (capab=0x11 status=0 aid=2)
[   82.979154] wlan0: associated
[   82.981123] wlan0: deauthenticating from 8a:02:71:a7:d6:fd by local choice (Reason: 2=PREV_AUTH_NOT_VALID)
[   87.032763] wlan0: authenticate with 6a:02:71:a7:d6:fd
[   87.047532] wlan0: bad VHT capabilities, disabling VHT
[   87.047543] wlan0: Invalid HE elem, Disable HE
[   87.047546] wlan0: 80 MHz not supported, disabling VHT
[   87.054708] wlan0: send auth to 6a:02:71:a7:d6:fd (try 1/3)
[   87.083567] wlan0: authenticated
[   87.109263] wlan0: associate with 6a:02:71:a7:d6:fd (try 1/3)
[   87.140986] wlan0: RX AssocResp from 6a:02:71:a7:d6:fd (capab=0x411 status=0 aid=3)
[   87.146227] wlan0: associated
[   92.998810] wlan0: disconnect from AP 6a:02:71:a7:d6:fd for new auth to 8a:02:71:a7:d6:fd
[   93.067652] wlan0: authenticate with 8a:02:71:a7:d6:fd
[   93.087948] wlan0: Invalid HE elem, Disable HE
[   93.098630] wlan0: send auth to 8a:02:71:a7:d6:fd (try 1/3)
[   93.126168] wlan0: authenticated
[   93.184399] wlan0: associate with 8a:02:71:a7:d6:fd (try 1/3)
[   93.185413] wlan0: RX AssocResp from 8a:02:71:a7:d6:fd (capab=0x11 status=30 aid=2)
[   93.185451] wlan0: 8a:02:71:a7:d6:fd rejected association temporarily; comeback duration 196 TU (200 ms)
[   93.387374] wlan0: associate with 8a:02:71:a7:d6:fd (try 2/3)
[   93.468025] wlan0: RX AssocResp from 8a:02:71:a7:d6:fd (capab=0x11 status=30 aid=2)
[   93.468079] wlan0: 8a:02:71:a7:d6:fd rejected association temporarily; comeback duration 196 TU (200 ms)
[   93.670767] wlan0: associate with 8a:02:71:a7:d6:fd (try 3/3)
[   93.753905] wlan0: RX AssocResp from 8a:02:71:a7:d6:fd (capab=0x11 status=30 aid=2)
[   93.753946] wlan0: 8a:02:71:a7:d6:fd rejected association temporarily; comeback duration 196 TU (200 ms)
[   93.857486] wlan0: association with 8a:02:71:a7:d6:fd timed out
[   97.649195] wlan0: authenticate with 6a:02:71:a7:d6:fd
[   97.685227] wlan0: bad VHT capabilities, disabling VHT
[   97.685238] wlan0: Invalid HE elem, Disable HE
[   97.685241] wlan0: 80 MHz not supported, disabling VHT
[   97.688820] wlan0: send auth to 6a:02:71:a7:d6:fd (try 1/3)
[   97.716515] wlan0: authenticated
[   97.738299] wlan0: associate with 6a:02:71:a7:d6:fd (try 1/3)
[   97.742809] wlan0: RX AssocResp from 6a:02:71:a7:d6:fd (capab=0x411 status=0 aid=3)
[   97.753345] wlan0: associated
[  111.622519] wlan0: disconnect from AP 6a:02:71:a7:d6:fd for new auth to 8a:02:71:a7:d6:fd
[  111.664050] wlan0: authenticate with 8a:02:71:a7:d6:fd
[  111.697401] wlan0: Invalid HE elem, Disable HE
[  111.701298] wlan0: send auth to 8a:02:71:a7:d6:fd (try 1/3)
[  111.730788] wlan0: authenticated
[  111.804031] wlan0: associate with 8a:02:71:a7:d6:fd (try 1/3)
[  111.805238] wlan0: RX AssocResp from 8a:02:71:a7:d6:fd (capab=0x11 status=0 aid=2)
[  111.818096] wlan0: associated
[  111.818156] wlan0: Limiting TX power to 24 (24 - 0) dBm as advertised by 8a:02:71:a7:d6:fd
[  111.818919] wlan0: deauthenticating from 8a:02:71:a7:d6:fd by local choice (Reason: 2=PREV_AUTH_NOT_VALID)
[  116.042735] wlan0: authenticate with 6a:02:71:a7:d6:fd
[  116.078615] wlan0: bad VHT capabilities, disabling VHT
[  116.078619] wlan0: Invalid HE elem, Disable HE
[  116.078620] wlan0: 80 MHz not supported, disabling VHT
[  116.081636] wlan0: send auth to 6a:02:71:a7:d6:fd (try 1/3)
[  116.112225] wlan0: authenticated
[  116.139601] wlan0: associate with 6a:02:71:a7:d6:fd (try 1/3)
[  116.158609] wlan0: RX AssocResp from 6a:02:71:a7:d6:fd (capab=0x411 status=0 aid=3)
[  116.165900] wlan0: associated
[  122.300255] wlan0: disconnect from AP 6a:02:71:a7:d6:fd for new auth to 8a:02:71:a7:d6:fd
[  122.351629] wlan0: authenticate with 8a:02:71:a7:d6:fd
[  122.371566] wlan0: Invalid HE elem, Disable HE
[  122.375709] wlan0: send auth to 8a:02:71:a7:d6:fd (try 1/3)
[  122.403774] wlan0: authenticated
[  122.458413] wlan0: associate with 8a:02:71:a7:d6:fd (try 1/3)
[  122.460031] wlan0: RX AssocResp from 8a:02:71:a7:d6:fd (capab=0x11 status=0 aid=2)
[  122.464988] wlan0: associated
[  122.558378] wlan0: Limiting TX power to 24 (24 - 0) dBm as advertised by 8a:02:71:a7:d6:fd
[  125.038168] audit: type=1130 audit(1666913213.341:103): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=NetworkManager-dispatcher comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[  135.042030] audit: type=1131 audit(1666913223.350:104): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=NetworkManager-dispatcher comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[  220.468188] audit: type=1334 audit(1666913308.821:105): prog-id=27 op=LOAD
[  220.468244] audit: type=1334 audit(1666913308.821:106): prog-id=28 op=LOAD
[  220.468259] audit: type=1334 audit(1666913308.821:107): prog-id=29 op=LOAD
[  220.551937] audit: type=1130 audit(1666913308.905:108): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-timedated comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[  220.582040] gnome-documents[3031]: segfault at 20 ip 00007f0983f61bd2 sp 00007ffeca09f950 error 4 in libtracker-sparql-2.0.so.0.306.0[7f0983f58000+1c000]
[  220.582047] Code: 40 48 85 f6 0f 84 ba 02 00 00 4c 89 ff ff 15 7d 1d 02 00 4c 89 f7 ff 15 8c 17 02 00 48 8b 4c 24 38 48 85 c9 0f 85 bd fd ff ff <48> 8b 43 20 c7 00 01 00 00 00 48 83 7c 24 30 00 0f 84 b8 00 00 00
[  220.582065] audit: type=1701 audit(1666913308.935:109): auid=1001 uid=1001 gid=1001 ses=4 pid=3031 comm="gnome-documents" exe="/usr/bin/gjs-console" sig=11 res=1
[  220.586646] audit: type=1334 audit(1666913308.941:110): prog-id=30 op=LOAD
[  220.586709] audit: type=1334 audit(1666913308.941:111): prog-id=31 op=LOAD
[  220.586726] audit: type=1334 audit(1666913308.941:112): prog-id=32 op=LOAD
[  220.587407] audit: type=1130 audit(1666913308.941:113): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-coredump@0-3162-0 comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[  250.569309] kauditd_printk_skb: 14 callbacks suppressed
[  250.569311] audit: type=1131 audit(1666913338.937:127): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-timedated comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[  250.604346] audit: type=1334 audit(1666913338.973:128): prog-id=0 op=UNLOAD
[  250.604350] audit: type=1334 audit(1666913338.973:129): prog-id=0 op=UNLOAD
[  250.604352] audit: type=1334 audit(1666913338.973:130): prog-id=0 op=UNLOAD
[  261.405543] gnome-documents[3528]: segfault at 20 ip 00007f3d3043cbd2 sp 00007ffd193c8f40 error 4 in libtracker-sparql-2.0.so.0.306.0[7f3d30433000+1c000]
[  261.405554] Code: 40 48 85 f6 0f 84 ba 02 00 00 4c 89 ff ff 15 7d 1d 02 00 4c 89 f7 ff 15 8c 17 02 00 48 8b 4c 24 38 48 85 c9 0f 85 bd fd ff ff <48> 8b 43 20 c7 00 01 00 00 00 48 83 7c 24 30 00 0f 84 b8 00 00 00
[  261.405582] audit: type=1701 audit(1666913349.782:131): auid=1001 uid=1001 gid=1001 ses=4 pid=3528 comm="gnome-documents" exe="/usr/bin/gjs-console" sig=11 res=1
[  261.411150] audit: type=1334 audit(1666913349.786:132): prog-id=36 op=LOAD
[  261.411204] audit: type=1334 audit(1666913349.786:133): prog-id=37 op=LOAD
[  261.411220] audit: type=1334 audit(1666913349.786:134): prog-id=38 op=LOAD
[  261.442384] audit: type=1130 audit(1666913349.819:135): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-coredump@2-3624-0 comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[  261.610158] audit: type=1131 audit(1666913349.982:136): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-coredump@2-3624-0 comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[  261.728710] audit: type=1334 audit(1666913350.102:137): prog-id=0 op=UNLOAD
[  261.728723] audit: type=1334 audit(1666913350.102:138): prog-id=0 op=UNLOAD
[  261.728727] audit: type=1334 audit(1666913350.102:139): prog-id=0 op=UNLOAD
[  388.088569] kauditd_printk_skb: 10 callbacks suppressed
[  388.088571] audit: type=1100 audit(1666913476.527:149): pid=4069 uid=1001 auid=1001 ses=4 msg='op=PAM:authentication grantors=pam_faillock,pam_permit,pam_faillock acct="nomade" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
[  388.088807] audit: type=1101 audit(1666913476.527:150): pid=4069 uid=1001 auid=1001 ses=4 msg='op=PAM:accounting grantors=pam_unix,pam_permit,pam_time acct="nomade" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
[  388.089293] audit: type=1110 audit(1666913476.527:151): pid=4069 uid=1001 auid=1001 ses=4 msg='op=PAM:setcred grantors=pam_faillock,pam_permit,pam_faillock acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
[  388.089367] audit: type=1105 audit(1666913476.527:152): pid=4069 uid=1001 auid=1001 ses=4 msg='op=PAM:session_open grantors=pam_systemd_home,pam_limits,pam_unix,pam_permit acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
[  391.986630] audit: type=1106 audit(1666913480.429:153): pid=4069 uid=1001 auid=1001 ses=4 msg='op=PAM:session_close grantors=pam_systemd_home,pam_limits,pam_unix,pam_permit acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
[  391.986680] audit: type=1104 audit(1666913480.429:154): pid=4069 uid=1001 auid=1001 ses=4 msg='op=PAM:setcred grantors=pam_faillock,pam_permit,pam_faillock acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
[  497.027669] audit: type=1101 audit(1666913585.521:155): pid=4193 uid=1001 auid=1001 ses=4 msg='op=PAM:accounting grantors=pam_unix,pam_permit,pam_time acct="nomade" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
[  497.028090] audit: type=1110 audit(1666913585.521:156): pid=4193 uid=1001 auid=1001 ses=4 msg='op=PAM:setcred grantors=pam_faillock,pam_permit,pam_env,pam_faillock acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
[  497.028165] audit: type=1105 audit(1666913585.521:157): pid=4193 uid=1001 auid=1001 ses=4 msg='op=PAM:session_open grantors=pam_systemd_home,pam_limits,pam_unix,pam_permit acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
[  504.351653] audit: type=1106 audit(1666913592.848:158): pid=4193 uid=1001 auid=1001 ses=4 msg='op=PAM:session_close grantors=pam_systemd_home,pam_limits,pam_unix,pam_permit acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
[  504.351669] audit: type=1104 audit(1666913592.848:159): pid=4193 uid=1001 auid=1001 ses=4 msg='op=PAM:setcred grantors=pam_faillock,pam_permit,pam_env,pam_faillock acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
[  690.537839] audit: type=1334 audit(1666913779.128:160): prog-id=42 op=LOAD
[  690.537891] audit: type=1334 audit(1666913779.128:161): prog-id=43 op=LOAD
[  690.537906] audit: type=1334 audit(1666913779.128:162): prog-id=44 op=LOAD
[  690.609714] audit: type=1130 audit(1666913779.202:163): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-hostnamed comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[  720.632428] audit: type=1131 audit(1666913809.237:164): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-hostnamed comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[  720.740807] audit: type=1334 audit(1666913809.347:165): prog-id=0 op=UNLOAD
[  720.740827] audit: type=1334 audit(1666913809.347:166): prog-id=0 op=UNLOAD
[  720.740834] audit: type=1334 audit(1666913809.347:167): prog-id=0 op=UNLOAD
[  776.950166] audit: type=1101 audit(1666913865.585:168): pid=4771 uid=1001 auid=1001 ses=4 msg='op=PAM:accounting grantors=pam_unix,pam_permit,pam_time acct="nomade" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
[  776.950439] audit: type=1110 audit(1666913865.585:169): pid=4771 uid=1001 auid=1001 ses=4 msg='op=PAM:setcred grantors=pam_faillock,pam_permit,pam_env,pam_faillock acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
[  776.950501] audit: type=1105 audit(1666913865.585:170): pid=4771 uid=1001 auid=1001 ses=4 msg='op=PAM:session_open grantors=pam_systemd_home,pam_limits,pam_unix,pam_permit acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
[  909.688759] audit: type=1130 audit(1666913998.388:171): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-tmpfiles-clean comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[  909.688764] audit: type=1131 audit(1666913998.388:172): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-tmpfiles-clean comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[  936.202625] audit: type=1100 audit(1666914024.915:173): pid=5035 uid=1001 auid=1001 ses=4 msg='op=PAM:authentication grantors=pam_faillock,pam_permit,pam_faillock acct="nomade" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/1 res=success'
[  936.202715] audit: type=1101 audit(1666914024.915:174): pid=5035 uid=1001 auid=1001 ses=4 msg='op=PAM:accounting grantors=pam_unix,pam_permit,pam_time acct="nomade" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/1 res=success'
[  936.203504] audit: type=1110 audit(1666914024.918:175): pid=5035 uid=1001 auid=1001 ses=4 msg='op=PAM:setcred grantors=pam_faillock,pam_permit,pam_faillock acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/1 res=success'
[  936.203569] audit: type=1105 audit(1666914024.918:176): pid=5035 uid=1001 auid=1001 ses=4 msg='op=PAM:session_open grantors=pam_systemd_home,pam_limits,pam_unix,pam_permit acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/1 res=success'
[  937.353073] audit: type=1106 audit(1666914026.069:177): pid=5035 uid=1001 auid=1001 ses=4 msg='op=PAM:session_close grantors=pam_systemd_home,pam_limits,pam_unix,pam_permit acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/1 res=success'
[  937.353140] audit: type=1104 audit(1666914026.069:178): pid=5035 uid=1001 auid=1001 ses=4 msg='op=PAM:setcred grantors=pam_faillock,pam_permit,pam_faillock acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/1 res=success'
[ 1090.911706] audit: type=1334 audit(1666914179.702:179): prog-id=45 op=LOAD
[ 1090.911758] audit: type=1334 audit(1666914179.702:180): prog-id=46 op=LOAD
[ 1090.911772] audit: type=1334 audit(1666914179.702:181): prog-id=47 op=LOAD
[ 1090.970506] audit: type=1130 audit(1666914179.762:182): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-hostnamed comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[ 1142.741390] audit: type=1131 audit(1666914231.558:183): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-hostnamed comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[ 1142.859675] audit: type=1334 audit(1666914231.678:184): prog-id=0 op=UNLOAD
[ 1142.859688] audit: type=1334 audit(1666914231.678:185): prog-id=0 op=UNLOAD
[ 1142.859695] audit: type=1334 audit(1666914231.678:186): prog-id=0 op=UNLOAD
[ 1403.680358] audit: type=1334 audit(1666914491.983:187): prog-id=48 op=LOAD
[ 1403.680425] audit: type=1334 audit(1666914491.983:188): prog-id=49 op=LOAD
[ 1403.680445] audit: type=1334 audit(1666914491.983:189): prog-id=50 op=LOAD
[ 1403.719681] audit: type=1130 audit(1666914492.023:190): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-hostnamed comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[ 1433.759961] audit: type=1131 audit(1666914522.060:191): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=systemd-hostnamed comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
[ 1433.859256] audit: type=1334 audit(1666914522.160:192): prog-id=0 op=UNLOAD
[ 1433.859262] audit: type=1334 audit(1666914522.160:193): prog-id=0 op=UNLOAD
[ 1433.859265] audit: type=1334 audit(1666914522.160:194): prog-id=0 op=UNLOAD
[ 1523.173750] audit: type=1100 audit(1666914611.484:195): pid=6026 uid=1001 auid=1001 ses=4 msg='op=PAM:authentication grantors=pam_faillock,pam_permit,pam_faillock acct="nomade" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/2 res=success'
[ 1523.173827] audit: type=1101 audit(1666914611.484:196): pid=6026 uid=1001 auid=1001 ses=4 msg='op=PAM:accounting grantors=pam_unix,pam_permit,pam_time acct="nomade" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/2 res=success'
[ 1523.174368] audit: type=1110 audit(1666914611.484:197): pid=6026 uid=1001 auid=1001 ses=4 msg='op=PAM:setcred grantors=pam_faillock,pam_permit,pam_faillock acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/2 res=success'
[ 1523.174430] audit: type=1105 audit(1666914611.484:198): pid=6026 uid=1001 auid=1001 ses=4 msg='op=PAM:session_open grantors=pam_systemd_home,pam_limits,pam_unix,pam_permit acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/2 res=success'
____________________________________________

Using built-in specs.
COLLECT_GCC=gcc
COLLECT_LTO_WRAPPER=/usr/lib/gcc/x86_64-pc-linux-gnu/12.2.0/lto-wrapper
Target: x86_64-pc-linux-gnu
Configured with: /build/gcc/src/gcc/configure --enable-languages=c,c++,ada,fortran,go,lto,objc,obj-c++,d --enable-bootstrap --prefix=/usr --libdir=/usr/lib --libexecdir=/usr/lib --mandir=/usr/share/man --infodir=/usr/share/info --with-bugurl=https://bugs.archlinux.org/ --with-build-config=bootstrap-lto --with-linker-hash-style=gnu --with-system-zlib --enable-__cxa_atexit --enable-cet=auto --enable-checking=release --enable-clocale=gnu --enable-default-pie --enable-default-ssp --enable-gnu-indirect-function --enable-gnu-unique-object --enable-libstdcxx-backtrace --enable-link-serialization=1 --enable-linker-build-id --enable-lto --enable-multilib --enable-plugin --enable-shared --enable-threads=posix --disable-libssp --disable-libstdcxx-pch --disable-werror
Thread model: posix
Supported LTO compression algorithms: zlib zstd
gcc version 12.2.0 (GCC) 
____________________________________________

Using built-in specs.
COLLECT_GCC=g++
COLLECT_LTO_WRAPPER=/usr/lib/gcc/x86_64-pc-linux-gnu/12.2.0/lto-wrapper
Target: x86_64-pc-linux-gnu
Configured with: /build/gcc/src/gcc/configure --enable-languages=c,c++,ada,fortran,go,lto,objc,obj-c++,d --enable-bootstrap --prefix=/usr --libdir=/usr/lib --libexecdir=/usr/lib --mandir=/usr/share/man --infodir=/usr/share/info --with-bugurl=https://bugs.archlinux.org/ --with-build-config=bootstrap-lto --with-linker-hash-style=gnu --with-system-zlib --enable-__cxa_atexit --enable-cet=auto --enable-checking=release --enable-clocale=gnu --enable-default-pie --enable-default-ssp --enable-gnu-indirect-function --enable-gnu-unique-object --enable-libstdcxx-backtrace --enable-link-serialization=1 --enable-linker-build-id --enable-lto --enable-multilib --enable-plugin --enable-shared --enable-threads=posix --disable-libssp --disable-libstdcxx-pch --disable-werror
Thread model: posix
Supported LTO compression algorithms: zlib zstd
gcc version 12.2.0 (GCC) 
____________________________________________

xset -q:

Keyboard Control:
  auto repeat:  on    key click percent:  0    LED mask:  00000002
  XKB indicators:
    00: Caps Lock:   off    01: Num Lock:    on     02: Scroll Lock: off
    03: Compose:     off    04: Kana:        off    05: Sleep:       off
    06: Suspend:     off    07: Mute:        off    08: Misc:        off
    09: Mail:        off    10: Charging:    off    11: Shift Lock:  off
    12: Group 2:     off    13: Mouse Keys:  off
  auto repeat delay:  500    repeat rate:  33
  auto repeating keys:  00ffffffdffffbbf
                        fadfffefffedffff
                        9fffffffffffffff
                        fff7ffffffffffff
  bell percent:  50    bell pitch:  400    bell duration:  100
Pointer Control:
  acceleration:  2/1    threshold:  4
Screen Saver:
  prefer blanking:  yes    allow exposures:  yes
  timeout:  0    cycle:  0
Colors:
  default colormap:  0x5d    BlackPixel:  0x0    WhitePixel:  0xffffff
Font Path:
  /usr/share/fonts/TTF,/usr/share/fonts/100dpi,/usr/share/fonts/75dpi,built-ins
DPMS (Energy Star):
  Server does not have the DPMS Extension
____________________________________________

nvidia-settings -q all:

./nvidia-bug-report.sh: line 924: nvidia-settings: command not found
____________________________________________

xrandr --verbose:

Screen 0: minimum 16 x 16, current 5760 x 2160, maximum 32767 x 32767
XWAYLAND0 connected 3840x2160+1920+0 (0x25) normal (normal left inverted right x axis y axis) 610mm x 350mm
	Identifier: 0x21
	Timestamp:  12261
	Subpixel:   unknown
	Gamma:      1.0:1.0:1.0
	Brightness: 0.0
	Clones:    
	CRTC:       1
	CRTCs:      1
	Transform:  1.000000 0.000000 0.000000
	            0.000000 1.000000 0.000000
	            0.000000 0.000000 1.000000
	           filter: 
	RANDR Emulation: 1 
	non-desktop: 0 
		supported: 0, 1
  3840x2160 (0x25) 338.750MHz -HSync +VSync *current +preferred
        h: width  3840 start 4080 end 4488 total 5136 skew    0 clock  65.96KHz
        v: height 2160 start 2163 end 2168 total 2200           clock  29.98Hz
  2048x1536 (0x26) 125.250MHz -HSync +VSync
        h: width  2048 start 2152 end 2360 total 2672 skew    0 clock  46.88KHz
        v: height 1536 start 1539 end 1543 total 1565           clock  29.95Hz
  1920x1440 (0x27) 109.750MHz -HSync +VSync
        h: width  1920 start 2016 end 2208 total 2496 skew    0 clock  43.97KHz
        v: height 1440 start 1443 end 1447 total 1468           clock  29.95Hz
  1600x1200 (0x28) 74.500MHz -HSync +VSync
        h: width  1600 start 1656 end 1816 total 2032 skew    0 clock  36.66KHz
        v: height 1200 start 1203 end 1207 total 1224           clock  29.95Hz
  1440x1080 (0x29) 59.500MHz -HSync +VSync
        h: width  1440 start 1488 end 1624 total 1808 skew    0 clock  32.91KHz
        v: height 1080 start 1083 end 1087 total 1102           clock  29.86Hz
  1400x1050 (0x2a) 56.250MHz -HSync +VSync
        h: width  1400 start 1440 end 1576 total 1752 skew    0 clock  32.11KHz
        v: height 1050 start 1053 end 1057 total 1071           clock  29.98Hz
  1280x1024 (0x2b) 50.000MHz -HSync +VSync
        h: width  1280 start 1320 end 1440 total 1600 skew    0 clock  31.25KHz
        v: height 1024 start 1027 end 1034 total 1045           clock  29.90Hz
  1280x960 (0x2c) 46.750MHz -HSync +VSync
        h: width  1280 start 1320 end 1440 total 1600 skew    0 clock  29.22KHz
        v: height  960 start  963 end  967 total  980           clock  29.82Hz
  1152x864 (0x2d) 38.000MHz -HSync +VSync
        h: width  1152 start 1184 end 1296 total 1440 skew    0 clock  26.39KHz
        v: height  864 start  867 end  871 total  882           clock  29.92Hz
  1024x768 (0x2e) 30.000MHz -HSync +VSync
        h: width  1024 start 1056 end 1152 total 1280 skew    0 clock  23.44KHz
        v: height  768 start  771 end  775 total  784           clock  29.89Hz
  800x600 (0x2f) 18.000MHz -HSync +VSync
        h: width   800 start  824 end  896 total  992 skew    0 clock  18.15KHz
        v: height  600 start  603 end  607 total  614           clock  29.55Hz
  640x480 (0x30) 11.750MHz -HSync +VSync
        h: width   640 start  664 end  720 total  800 skew    0 clock  14.69KHz
        v: height  480 start  483 end  487 total  492           clock  29.85Hz
  320x240 (0x31)  2.750MHz -HSync +VSync
        h: width   320 start  336 end  360 total  400 skew    0 clock   6.88KHz
        v: height  240 start  243 end  247 total  250           clock  27.50Hz
  2560x1600 (0x32) 164.250MHz -HSync +VSync
        h: width  2560 start 2696 end 2960 total 3360 skew    0 clock  48.88KHz
        v: height 1600 start 1603 end 1609 total 1630           clock  29.99Hz
  1920x1200 (0x33) 89.750MHz -HSync +VSync
        h: width  1920 start 1992 end 2184 total 2448 skew    0 clock  36.66KHz
        v: height 1200 start 1203 end 1209 total 1224           clock  29.95Hz
  1680x1050 (0x34) 67.750MHz -HSync +VSync
        h: width  1680 start 1736 end 1896 total 2112 skew    0 clock  32.08KHz
        v: height 1050 start 1053 end 1059 total 1071           clock  29.95Hz
  1440x900 (0x35) 49.250MHz -HSync +VSync
        h: width  1440 start 1480 end 1616 total 1792 skew    0 clock  27.48KHz
        v: height  900 start  903 end  909 total  919           clock  29.91Hz
  1280x800 (0x36) 39.000MHz -HSync +VSync
        h: width  1280 start 1320 end 1440 total 1600 skew    0 clock  24.38KHz
        v: height  800 start  803 end  809 total  817           clock  29.83Hz
  720x480 (0x37) 13.000MHz -HSync +VSync
        h: width   720 start  744 end  808 total  896 skew    0 clock  14.51KHz
        v: height  480 start  483 end  493 total  496           clock  29.25Hz
  640x400 (0x38)  9.750MHz -HSync +VSync
        h: width   640 start  664 end  720 total  800 skew    0 clock  12.19KHz
        v: height  400 start  403 end  409 total  412           clock  29.58Hz
  320x200 (0x39)  2.250MHz -HSync +VSync
        h: width   320 start  336 end  360 total  400 skew    0 clock   5.62KHz
        v: height  200 start  203 end  209 total  212           clock  26.53Hz
  3200x1800 (0x3a) 233.000MHz -HSync +VSync
        h: width  3200 start 3384 end 3720 total 4240 skew    0 clock  54.95KHz
        v: height 1800 start 1803 end 1808 total 1834           clock  29.96Hz
  2880x1620 (0x3b) 186.750MHz -HSync +VSync
        h: width  2880 start 3032 end 3328 total 3776 skew    0 clock  49.46KHz
        v: height 1620 start 1623 end 1628 total 1651           clock  29.96Hz
  2560x1440 (0x3c) 146.250MHz -HSync +VSync
        h: width  2560 start 2680 end 2944 total 3328 skew    0 clock  43.95KHz
        v: height 1440 start 1443 end 1448 total 1468           clock  29.94Hz
  2048x1152 (0x3d) 91.750MHz -HSync +VSync
        h: width  2048 start 2128 end 2328 total 2608 skew    0 clock  35.18KHz
        v: height 1152 start 1155 end 1160 total 1175           clock  29.94Hz
  1920x1080 (0x3e) 79.750MHz -HSync +VSync
        h: width  1920 start 1976 end 2168 total 2416 skew    0 clock  33.01KHz
        v: height 1080 start 1083 end 1088 total 1102           clock  29.95Hz
  1600x900 (0x3f) 55.000MHz -HSync +VSync
        h: width  1600 start 1648 end 1800 total 2000 skew    0 clock  27.50KHz
        v: height  900 start  903 end  908 total  919           clock  29.92Hz
  1368x768 (0x40) 40.000MHz -HSync +VSync
        h: width  1368 start 1408 end 1536 total 1704 skew    0 clock  23.47KHz
        v: height  768 start  771 end  781 total  784           clock  29.94Hz
  1280x720 (0x41) 35.250MHz -HSync +VSync
        h: width  1280 start 1320 end 1440 total 1600 skew    0 clock  22.03KHz
        v: height  720 start  723 end  728 total  736           clock  29.93Hz
  1024x576 (0x42) 22.500MHz -HSync +VSync
        h: width  1024 start 1056 end 1152 total 1280 skew    0 clock  17.58KHz
        v: height  576 start  579 end  584 total  589           clock  29.84Hz
  864x486 (0x43) 15.750MHz -HSync +VSync
        h: width   864 start  888 end  968 total 1072 skew    0 clock  14.69KHz
        v: height  486 start  489 end  494 total  498           clock  29.50Hz
  720x400 (0x44) 11.000MHz -HSync +VSync
        h: width   720 start  744 end  808 total  896 skew    0 clock  12.28KHz
        v: height  400 start  403 end  413 total  416           clock  29.51Hz
  640x350 (0x45)  8.500MHz -HSync +VSync
        h: width   640 start  664 end  720 total  800 skew    0 clock  10.62KHz
        v: height  350 start  353 end  363 total  366           clock  29.03Hz
XWAYLAND1 connected primary 1920x1080+0+0 (0x46) normal (normal left inverted right x axis y axis) 340mm x 190mm
	Identifier: 0x23
	Timestamp:  12261
	Subpixel:   unknown
	Gamma:      1.0:1.0:1.0
	Brightness: 0.0
	Clones:    
	CRTC:       0
	CRTCs:      0
	Transform:  1.000000 0.000000 0.000000
	            0.000000 1.000000 0.000000
	            0.000000 0.000000 1.000000
	           filter: 
	RANDR Emulation: 1 
	non-desktop: 0 
		supported: 0, 1
  1920x1080 (0x46) 452.500MHz -HSync +VSync *current +preferred
        h: width  1920 start 2088 end 2296 total 2672 skew    0 clock 169.35KHz
        v: height 1080 start 1083 end 1088 total 1177           clock 143.88Hz
  1440x1080 (0x47) 338.500MHz -HSync +VSync
        h: width  1440 start 1568 end 1720 total 2000 skew    0 clock 169.25KHz
        v: height 1080 start 1083 end 1087 total 1177           clock 143.80Hz
  1400x1050 (0x48) 320.000MHz -HSync +VSync
        h: width  1400 start 1520 end 1672 total 1944 skew    0 clock 164.61KHz
        v: height 1050 start 1053 end 1057 total 1144           clock 143.89Hz
  1280x1024 (0x49) 285.000MHz -HSync +VSync
        h: width  1280 start 1392 end 1528 total 1776 skew    0 clock 160.47KHz
        v: height 1024 start 1027 end 1034 total 1116           clock 143.79Hz
  1280x960 (0x4a) 267.250MHz -HSync +VSync
        h: width  1280 start 1392 end 1528 total 1776 skew    0 clock 150.48KHz
        v: height  960 start  963 end  967 total 1046           clock 143.86Hz
  1152x864 (0x4b) 214.750MHz -HSync +VSync
        h: width  1152 start 1248 end 1368 total 1584 skew    0 clock 135.57KHz
        v: height  864 start  867 end  871 total  942           clock 143.92Hz
  1024x768 (0x4c) 169.750MHz -HSync +VSync
        h: width  1024 start 1112 end 1216 total 1408 skew    0 clock 120.56KHz
        v: height  768 start  771 end  775 total  838           clock 143.87Hz
  800x600 (0x4d) 102.500MHz -HSync +VSync
        h: width   800 start  864 end  944 total 1088 skew    0 clock  94.21KHz
        v: height  600 start  603 end  607 total  655           clock 143.83Hz
  640x480 (0x4e) 65.250MHz -HSync +VSync
        h: width   640 start  688 end  752 total  864 skew    0 clock  75.52KHz
        v: height  480 start  483 end  487 total  525           clock 143.85Hz
  320x240 (0x4f) 15.000MHz -HSync +VSync
        h: width   320 start  336 end  360 total  400 skew    0 clock  37.50KHz
        v: height  240 start  243 end  247 total  264           clock 142.05Hz
  1680x1050 (0x50) 384.500MHz -HSync +VSync
        h: width  1680 start 1824 end 2008 total 2336 skew    0 clock 164.60KHz
        v: height 1050 start 1053 end 1059 total 1144           clock 143.88Hz
  1440x900 (0x51) 280.000MHz -HSync +VSync
        h: width  1440 start 1560 end 1712 total 1984 skew    0 clock 141.13KHz
        v: height  900 start  903 end  909 total  981           clock 143.86Hz
  1280x800 (0x52) 221.000MHz -HSync +VSync
        h: width  1280 start 1384 end 1520 total 1760 skew    0 clock 125.57KHz
        v: height  800 start  803 end  809 total  873           clock 143.84Hz
  720x480 (0x53) 72.500MHz -HSync +VSync
        h: width   720 start  768 end  840 total  960 skew    0 clock  75.52KHz
        v: height  480 start  483 end  493 total  525           clock 143.85Hz
  640x400 (0x54) 53.250MHz -HSync +VSync
        h: width   640 start  680 end  744 total  848 skew    0 clock  62.79KHz
        v: height  400 start  403 end  409 total  438           clock 143.37Hz
  320x200 (0x55) 12.500MHz -HSync +VSync
        h: width   320 start  336 end  360 total  400 skew    0 clock  31.25KHz
        v: height  200 start  203 end  209 total  221           clock 141.40Hz
  1600x900 (0x56) 311.750MHz -HSync +VSync
        h: width  1600 start 1736 end 1904 total 2208 skew    0 clock 141.19KHz
        v: height  900 start  903 end  908 total  981           clock 143.93Hz
  1368x768 (0x57) 226.500MHz -HSync +VSync
        h: width  1368 start 1480 end 1624 total 1880 skew    0 clock 120.48KHz
        v: height  768 start  771 end  781 total  838           clock 143.77Hz
  1280x720 (0x58) 198.750MHz -HSync +VSync
        h: width  1280 start 1384 end 1520 total 1760 skew    0 clock 112.93KHz
        v: height  720 start  723 end  728 total  786           clock 143.67Hz
  1024x576 (0x59) 126.000MHz -HSync +VSync
        h: width  1024 start 1104 end 1208 total 1392 skew    0 clock  90.52KHz
        v: height  576 start  579 end  584 total  629           clock 143.91Hz
  864x486 (0x5a) 89.250MHz -HSync +VSync
        h: width   864 start  928 end 1016 total 1168 skew    0 clock  76.41KHz
        v: height  486 start  489 end  494 total  532           clock 143.63Hz
  720x400 (0x5b) 60.500MHz -HSync +VSync
        h: width   720 start  768 end  840 total  960 skew    0 clock  63.02KHz
        v: height  400 start  403 end  413 total  438           clock 143.88Hz
  640x350 (0x5c) 46.750MHz -HSync +VSync
        h: width   640 start  680 end  744 total  848 skew    0 clock  55.13KHz
        v: height  350 start  353 end  363 total  384           clock 143.57Hz
____________________________________________

Running window manager properties:

_NET_SUPPORTING_WM_CHECK(WINDOW): window id # 0x800006
_MUTTER_VERSION(UTF8_STRING) = "42.5"
_GNOME_WM_KEYBINDINGS(UTF8_STRING) = "Mutter,GNOME Shell"
_NET_WM_NAME(UTF8_STRING) = "GNOME Shell"
____________________________________________

*** /proc/cmdline
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:24:48.609999997 -0300 /proc/cmdline
initrd=\amd-ucode.img initrd=\initramfs-linux.img root=PARTUUID=f407dfcd-5b75-c540-99c7-811fac3135b7 rw

____________________________________________

*** /proc/cpuinfo
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:24:49.049999989 -0300 /proc/cpuinfo
processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 25
model		: 80
model name	: AMD Ryzen 7 5800H with Radeon Graphics
stepping	: 0
microcode	: 0xa50000c
cpu MHz		: 1396.787
cache size	: 512 KB
physical id	: 0
siblings	: 16
core id		: 0
cpu cores	: 8
apicid		: 0
initial apicid	: 0
fpu		: yes
fpu_exception	: yes
cpuid level	: 16
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip pku ospke vaes vpclmulqdq rdpid overflow_recov succor smca fsrm
bugs		: sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
bogomips	: 6390.82
TLB size	: 2560 4K pages
clflush size	: 64
cache_alignment	: 64
address sizes	: 48 bits physical, 48 bits virtual
power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]

processor	: 1
vendor_id	: AuthenticAMD
cpu family	: 25
model		: 80
model name	: AMD Ryzen 7 5800H with Radeon Graphics
stepping	: 0
microcode	: 0xa50000c
cpu MHz		: 3200.000
cache size	: 512 KB
physical id	: 0
siblings	: 16
core id		: 0
cpu cores	: 8
apicid		: 1
initial apicid	: 1
fpu		: yes
fpu_exception	: yes
cpuid level	: 16
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip pku ospke vaes vpclmulqdq rdpid overflow_recov succor smca fsrm
bugs		: sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
bogomips	: 6390.82
TLB size	: 2560 4K pages
clflush size	: 64
cache_alignment	: 64
address sizes	: 48 bits physical, 48 bits virtual
power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]

processor	: 2
vendor_id	: AuthenticAMD
cpu family	: 25
model		: 80
model name	: AMD Ryzen 7 5800H with Radeon Graphics
stepping	: 0
microcode	: 0xa50000c
cpu MHz		: 2663.118
cache size	: 512 KB
physical id	: 0
siblings	: 16
core id		: 1
cpu cores	: 8
apicid		: 2
initial apicid	: 2
fpu		: yes
fpu_exception	: yes
cpuid level	: 16
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip pku ospke vaes vpclmulqdq rdpid overflow_recov succor smca fsrm
bugs		: sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
bogomips	: 6390.82
TLB size	: 2560 4K pages
clflush size	: 64
cache_alignment	: 64
address sizes	: 48 bits physical, 48 bits virtual
power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]

processor	: 3
vendor_id	: AuthenticAMD
cpu family	: 25
model		: 80
model name	: AMD Ryzen 7 5800H with Radeon Graphics
stepping	: 0
microcode	: 0xa50000c
cpu MHz		: 1200.000
cache size	: 512 KB
physical id	: 0
siblings	: 16
core id		: 1
cpu cores	: 8
apicid		: 3
initial apicid	: 3
fpu		: yes
fpu_exception	: yes
cpuid level	: 16
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip pku ospke vaes vpclmulqdq rdpid overflow_recov succor smca fsrm
bugs		: sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
bogomips	: 6390.82
TLB size	: 2560 4K pages
clflush size	: 64
cache_alignment	: 64
address sizes	: 48 bits physical, 48 bits virtual
power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]

processor	: 4
vendor_id	: AuthenticAMD
cpu family	: 25
model		: 80
model name	: AMD Ryzen 7 5800H with Radeon Graphics
stepping	: 0
microcode	: 0xa50000c
cpu MHz		: 1396.354
cache size	: 512 KB
physical id	: 0
siblings	: 16
core id		: 2
cpu cores	: 8
apicid		: 4
initial apicid	: 4
fpu		: yes
fpu_exception	: yes
cpuid level	: 16
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip pku ospke vaes vpclmulqdq rdpid overflow_recov succor smca fsrm
bugs		: sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
bogomips	: 6390.82
TLB size	: 2560 4K pages
clflush size	: 64
cache_alignment	: 64
address sizes	: 48 bits physical, 48 bits virtual
power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]

processor	: 5
vendor_id	: AuthenticAMD
cpu family	: 25
model		: 80
model name	: AMD Ryzen 7 5800H with Radeon Graphics
stepping	: 0
microcode	: 0xa50000c
cpu MHz		: 3200.000
cache size	: 512 KB
physical id	: 0
siblings	: 16
core id		: 2
cpu cores	: 8
apicid		: 5
initial apicid	: 5
fpu		: yes
fpu_exception	: yes
cpuid level	: 16
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip pku ospke vaes vpclmulqdq rdpid overflow_recov succor smca fsrm
bugs		: sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
bogomips	: 6390.82
TLB size	: 2560 4K pages
clflush size	: 64
cache_alignment	: 64
address sizes	: 48 bits physical, 48 bits virtual
power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]

processor	: 6
vendor_id	: AuthenticAMD
cpu family	: 25
model		: 80
model name	: AMD Ryzen 7 5800H with Radeon Graphics
stepping	: 0
microcode	: 0xa50000c
cpu MHz		: 1204.245
cache size	: 512 KB
physical id	: 0
siblings	: 16
core id		: 3
cpu cores	: 8
apicid		: 6
initial apicid	: 6
fpu		: yes
fpu_exception	: yes
cpuid level	: 16
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip pku ospke vaes vpclmulqdq rdpid overflow_recov succor smca fsrm
bugs		: sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
bogomips	: 6390.82
TLB size	: 2560 4K pages
clflush size	: 64
cache_alignment	: 64
address sizes	: 48 bits physical, 48 bits virtual
power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]

processor	: 7
vendor_id	: AuthenticAMD
cpu family	: 25
model		: 80
model name	: AMD Ryzen 7 5800H with Radeon Graphics
stepping	: 0
microcode	: 0xa50000c
cpu MHz		: 1213.768
cache size	: 512 KB
physical id	: 0
siblings	: 16
core id		: 3
cpu cores	: 8
apicid		: 7
initial apicid	: 7
fpu		: yes
fpu_exception	: yes
cpuid level	: 16
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip pku ospke vaes vpclmulqdq rdpid overflow_recov succor smca fsrm
bugs		: sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
bogomips	: 6390.82
TLB size	: 2560 4K pages
clflush size	: 64
cache_alignment	: 64
address sizes	: 48 bits physical, 48 bits virtual
power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]

processor	: 8
vendor_id	: AuthenticAMD
cpu family	: 25
model		: 80
model name	: AMD Ryzen 7 5800H with Radeon Graphics
stepping	: 0
microcode	: 0xa50000c
cpu MHz		: 3274.557
cache size	: 512 KB
physical id	: 0
siblings	: 16
core id		: 4
cpu cores	: 8
apicid		: 8
initial apicid	: 8
fpu		: yes
fpu_exception	: yes
cpuid level	: 16
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip pku ospke vaes vpclmulqdq rdpid overflow_recov succor smca fsrm
bugs		: sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
bogomips	: 6390.82
TLB size	: 2560 4K pages
clflush size	: 64
cache_alignment	: 64
address sizes	: 48 bits physical, 48 bits virtual
power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]

processor	: 9
vendor_id	: AuthenticAMD
cpu family	: 25
model		: 80
model name	: AMD Ryzen 7 5800H with Radeon Graphics
stepping	: 0
microcode	: 0xa50000c
cpu MHz		: 1200.000
cache size	: 512 KB
physical id	: 0
siblings	: 16
core id		: 4
cpu cores	: 8
apicid		: 9
initial apicid	: 9
fpu		: yes
fpu_exception	: yes
cpuid level	: 16
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip pku ospke vaes vpclmulqdq rdpid overflow_recov succor smca fsrm
bugs		: sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
bogomips	: 6390.82
TLB size	: 2560 4K pages
clflush size	: 64
cache_alignment	: 64
address sizes	: 48 bits physical, 48 bits virtual
power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]

processor	: 10
vendor_id	: AuthenticAMD
cpu family	: 25
model		: 80
model name	: AMD Ryzen 7 5800H with Radeon Graphics
stepping	: 0
microcode	: 0xa50000c
cpu MHz		: 2503.615
cache size	: 512 KB
physical id	: 0
siblings	: 16
core id		: 5
cpu cores	: 8
apicid		: 10
initial apicid	: 10
fpu		: yes
fpu_exception	: yes
cpuid level	: 16
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip pku ospke vaes vpclmulqdq rdpid overflow_recov succor smca fsrm
bugs		: sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
bogomips	: 6390.82
TLB size	: 2560 4K pages
clflush size	: 64
cache_alignment	: 64
address sizes	: 48 bits physical, 48 bits virtual
power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]

processor	: 11
vendor_id	: AuthenticAMD
cpu family	: 25
model		: 80
model name	: AMD Ryzen 7 5800H with Radeon Graphics
stepping	: 0
microcode	: 0xa50000c
cpu MHz		: 1200.000
cache size	: 512 KB
physical id	: 0
siblings	: 16
core id		: 5
cpu cores	: 8
apicid		: 11
initial apicid	: 11
fpu		: yes
fpu_exception	: yes
cpuid level	: 16
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip pku ospke vaes vpclmulqdq rdpid overflow_recov succor smca fsrm
bugs		: sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
bogomips	: 6390.82
TLB size	: 2560 4K pages
clflush size	: 64
cache_alignment	: 64
address sizes	: 48 bits physical, 48 bits virtual
power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]

processor	: 12
vendor_id	: AuthenticAMD
cpu family	: 25
model		: 80
model name	: AMD Ryzen 7 5800H with Radeon Graphics
stepping	: 0
microcode	: 0xa50000c
cpu MHz		: 2134.596
cache size	: 512 KB
physical id	: 0
siblings	: 16
core id		: 6
cpu cores	: 8
apicid		: 12
initial apicid	: 12
fpu		: yes
fpu_exception	: yes
cpuid level	: 16
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip pku ospke vaes vpclmulqdq rdpid overflow_recov succor smca fsrm
bugs		: sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
bogomips	: 6390.82
TLB size	: 2560 4K pages
clflush size	: 64
cache_alignment	: 64
address sizes	: 48 bits physical, 48 bits virtual
power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]

processor	: 13
vendor_id	: AuthenticAMD
cpu family	: 25
model		: 80
model name	: AMD Ryzen 7 5800H with Radeon Graphics
stepping	: 0
microcode	: 0xa50000c
cpu MHz		: 1200.000
cache size	: 512 KB
physical id	: 0
siblings	: 16
core id		: 6
cpu cores	: 8
apicid		: 13
initial apicid	: 13
fpu		: yes
fpu_exception	: yes
cpuid level	: 16
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip pku ospke vaes vpclmulqdq rdpid overflow_recov succor smca fsrm
bugs		: sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
bogomips	: 6390.82
TLB size	: 2560 4K pages
clflush size	: 64
cache_alignment	: 64
address sizes	: 48 bits physical, 48 bits virtual
power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]

processor	: 14
vendor_id	: AuthenticAMD
cpu family	: 25
model		: 80
model name	: AMD Ryzen 7 5800H with Radeon Graphics
stepping	: 0
microcode	: 0xa50000c
cpu MHz		: 2484.370
cache size	: 512 KB
physical id	: 0
siblings	: 16
core id		: 7
cpu cores	: 8
apicid		: 14
initial apicid	: 14
fpu		: yes
fpu_exception	: yes
cpuid level	: 16
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip pku ospke vaes vpclmulqdq rdpid overflow_recov succor smca fsrm
bugs		: sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
bogomips	: 6390.82
TLB size	: 2560 4K pages
clflush size	: 64
cache_alignment	: 64
address sizes	: 48 bits physical, 48 bits virtual
power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]

processor	: 15
vendor_id	: AuthenticAMD
cpu family	: 25
model		: 80
model name	: AMD Ryzen 7 5800H with Radeon Graphics
stepping	: 0
microcode	: 0xa50000c
cpu MHz		: 1200.000
cache size	: 512 KB
physical id	: 0
siblings	: 16
core id		: 7
cpu cores	: 8
apicid		: 15
initial apicid	: 15
fpu		: yes
fpu_exception	: yes
cpuid level	: 16
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf rapl pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 smep bmi2 erms invpcid cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local clzero irperf xsaveerptr rdpru wbnoinvd cppc arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif v_spec_ctrl umip pku ospke vaes vpclmulqdq rdpid overflow_recov succor smca fsrm
bugs		: sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
bogomips	: 6390.82
TLB size	: 2560 4K pages
clflush size	: 64
cache_alignment	: 64
address sizes	: 48 bits physical, 48 bits virtual
power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]


____________________________________________

*** /proc/interrupts
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:48:26.834765607 -0300 /proc/interrupts
            CPU0       CPU1       CPU2       CPU3       CPU4       CPU5       CPU6       CPU7       CPU8       CPU9       CPU10      CPU11      CPU12      CPU13      CPU14      CPU15      
   0:         42          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-IO-APIC    2-edge      timer
   1:          0          0          0          0          0          0          0          0          0          0          0          0         11          0          0          0  IR-IO-APIC    1-edge      i8042
   6:          0          0        699          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-IO-APIC    6-edge      AMDI0010:03
   7:          0          0          0          0          2          0          0          0          0          0          0          0          0          0          0          0  IR-IO-APIC    7-fasteoi   pinctrl_amd
   8:          0          0          0          0          0          0          0          0          0          0          0          1          0          0          0          0  IR-IO-APIC    8-edge      rtc0
   9:          0         34          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-IO-APIC    9-fasteoi   acpi
  25:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IOMMU-MSI    0-edge      AMD-Vi
  26:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  amd_gpio    0  ACPI:Event
  27:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  amd_gpio   23  ACPI:Event
  28:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  amd_gpio   44  ACPI:Event
  29:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  amd_gpio   61  ACPI:Event
  30:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  amd_gpio   62  ACPI:Event
  31:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  amd_gpio   58  ACPI:Event
  32:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  amd_gpio   59  ACPI:Event
  33:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  amd_gpio   21  ACPI:Event
  34:          0          0          0          0          0          1          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 18432-edge      PCIe PME, pciehp
  35:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 34816-edge      PCIe PME
  36:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 36864-edge      PCIe PME
  37:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 38912-edge      PCIe PME
  38:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 40960-edge      PCIe PME
  39:          0          0          0          0          0          0          0          0          0          0          1          0          0          0          0          0  IR-PCI-MSI 133120-edge      PCIe PME
  41:          0          0          0          0          0          0          0          0          0          0          0          0          0        120          0          0  IR-PCI-MSI 3151872-edge      xhci_hcd
  42:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 3151873-edge      xhci_hcd
  43:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 3151874-edge      xhci_hcd
  44:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 3151875-edge      xhci_hcd
  45:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 3151876-edge      xhci_hcd
  46:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 3151877-edge      xhci_hcd
  47:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 3151878-edge      xhci_hcd
  48:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 3151879-edge      xhci_hcd
  50:          0          0          0          0          0      75764          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 3153920-edge      xhci_hcd
  51:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 3153921-edge      xhci_hcd
  52:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 3153922-edge      xhci_hcd
  53:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 3153923-edge      xhci_hcd
  54:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 3153924-edge      xhci_hcd
  55:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 3153925-edge      xhci_hcd
  56:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 3153926-edge      xhci_hcd
  57:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 3153927-edge      xhci_hcd
  60:          0          0          0          0          0          0          0          0          0          0          0          0          0          0       3087          0  IR-PCI-MSI 2097152-edge      nvme0q0
  61:          0          0          0          0          0          0          0          0          0          0          0          0          0       3071          0          0  IR-PCI-MSI 2621440-edge      nvme1q0
  62:       7585          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 2097153-edge      nvme0q1
  63:          0       3606          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 2097154-edge      nvme0q2
  64:          0          0      17891          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 2097155-edge      nvme0q3
  65:          0          0          0       7278          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 2097156-edge      nvme0q4
  66:          0          0          0          0       6674          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 2097157-edge      nvme0q5
  67:          0          0          0          0          0       2063          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 2097158-edge      nvme0q6
  68:          0          0          0          0          0          0       5622          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 2097159-edge      nvme0q7
  69:          0          0          0          0          0          0          0       5100          0          0          0          0          0          0          0          0  IR-PCI-MSI 2097160-edge      nvme0q8
  70:          0          0          0          0          0          0          0          0       7923          0          0          0          0          0          0          0  IR-PCI-MSI 2097161-edge      nvme0q9
  71:          0          0          0          0          0          0          0          0          0       2528          0          0          0          0          0          0  IR-PCI-MSI 2097162-edge      nvme0q10
  72:          0          0          0          0          0          0          0          0          0          0       6170          0          0          0          0          0  IR-PCI-MSI 2097163-edge      nvme0q11
  73:          0          0          0          0          0          0          0          0          0          0          0       1641          0          0          0          0  IR-PCI-MSI 2097164-edge      nvme0q12
  74:          0          0          0          0          0          0          0          0          0          0          0          0       6014          0          0          0  IR-PCI-MSI 2097165-edge      nvme0q13
  75:          0          0          0          0          0          0          0          0          0          0          0          0          0       1663          0          0  IR-PCI-MSI 2097166-edge      nvme0q14
  76:          0          0          0          0          0          0          0          0          0          0          0          0          0          0      17045          0  IR-PCI-MSI 2097167-edge      nvme0q15
  77:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0      11312  IR-PCI-MSI 2097168-edge      nvme0q16
  78:          0        156          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 2621441-edge      nvme1q1
  79:          0          0          0         56          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 2621442-edge      nvme1q2
  80:          0          0          0          0          0         16          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 2621443-edge      nvme1q3
  81:          0          0          0          0          0          0          0         27          0          0          0          0          0          0          0          0  IR-PCI-MSI 2621444-edge      nvme1q4
  82:          0          0          0          0          0          0          0          0          0         55          0          0          0          0          0          0  IR-PCI-MSI 2621445-edge      nvme1q5
  83:          0          0          0          0          0          0          0          0          0          0          0         21          0          0          0          0  IR-PCI-MSI 2621446-edge      nvme1q6
  84:          0          0          0          0          0          0          0          0          0          0          0          0          0         89          0          0  IR-PCI-MSI 2621447-edge      nvme1q7
  85:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          4  IR-PCI-MSI 2621448-edge      nvme1q8
  86:          0          0          0          0          1          0          0          0          0          0          0          0          0          0          0          0  amd_gpio    9  ELAN1203:00
  88:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 3149824-edge      psp-1
  90:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 1048576-edge      enp2s0
  92:      70412          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 1572864-edge      iwlwifi:default_queue
  93:       3348          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 1572865-edge      iwlwifi:queue_1
  94:          0       2462          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 1572866-edge      iwlwifi:queue_2
  95:          0          0       4470          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 1572867-edge      iwlwifi:queue_3
  96:          0          0          0       1219          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 1572868-edge      iwlwifi:queue_4
  97:          0          0          0          0      36741          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 1572869-edge      iwlwifi:queue_5
  98:          0          0          0          0          0      13111          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 1572870-edge      iwlwifi:queue_6
  99:          0          0          0          0          0          0        410          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 1572871-edge      iwlwifi:queue_7
 100:          0          0          0          0          0          0          0        453          0          0          0          0          0          0          0          0  IR-PCI-MSI 1572872-edge      iwlwifi:queue_8
 101:          0          0          0          0          0          0          0          0        693          0          0          0          0          0          0          0  IR-PCI-MSI 1572873-edge      iwlwifi:queue_9
 102:          0          0          0          0          0          0          0          0          0       4868          0          0          0          0          0          0  IR-PCI-MSI 1572874-edge      iwlwifi:queue_10
 103:          0          0          0          0          0          0          0          0          0          0        463          0          0          0          0          0  IR-PCI-MSI 1572875-edge      iwlwifi:queue_11
 104:          0          0          0          0          0          0          0          0          0          0          0       4593          0          0          0          0  IR-PCI-MSI 1572876-edge      iwlwifi:queue_12
 105:          0          0          0          0          0          0          0          0          0          0          0          0       5964          0          0          0  IR-PCI-MSI 1572877-edge      iwlwifi:queue_13
 106:          0          0          0          0          0          0          0          0          0          0          0          0          0      14759          0          0  IR-PCI-MSI 1572878-edge      iwlwifi:queue_14
 107:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          7  IR-PCI-MSI 1572879-edge      iwlwifi:exception
 108:          0          0          0          0          0          0          0          0          0          0          0          0          0          0    2310449          0  IR-PCI-MSI 3145728-edge      amdgpu
 110:          0        177          0          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 3147776-edge      snd_hda_intel:card0
 111:          0          0       2120          0          0          0          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 3158016-edge      snd_hda_intel:card1
 112:          0          0          0          0        157          0          0          0          0          0          0          0          0          0          0          0  IR-IO-APIC    1-fasteoi   snd_hda_intel:card2
 114:          0          0          0          0          0        882          0          0          0          0          0          0          0          0          0          0  IR-PCI-MSI 524288-edge      nvidia
 NMI:          3          2          4          2          3          2          3          2          3          3          3          2          3          2          4          2   Non-maskable interrupts
 LOC:     174980     115559     139702      79847     160893      65213     196787      77829     129582      72711     129666      61469     124708      62298     166453      75177   Local timer interrupts
 SPU:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0   Spurious interrupts
 PMI:          3          2          4          2          3          2          3          2          3          3          3          2          3          2          4          2   Performance monitoring interrupts
 IWI:          0          0          0          0          2          0          0          0          0          1          0          0          0          0      34799          0   IRQ work interrupts
 RTR:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0   APIC ICR read retries
 RES:       1039       1305       1002        731       3462       1813      15475       4227        912        639        867        662        831        713        684        548   Rescheduling interrupts
 CAL:     384300     247744     383151     225480     336671     227205     365075     150483     325505     263991     389650     286934     349874     235535     267479     292890   Function call interrupts
 TLB:      16754      14980      16973      13651      17276      13942      17004      15970      16884      12894      16494      13755      16277      13520      16563      14556   TLB shootdowns
 TRM:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0   Thermal event interrupts
 THR:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0   Threshold APIC interrupts
 DFR:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0   Deferred Error APIC interrupts
 MCE:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0   Machine check exceptions
 MCP:          5          5          5          5          5          5          5          5          5          5          5          5          5          5          5          5   Machine check polls
 ERR:          0
 MIS:          0
 PIN:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0   Posted-interrupt notification event
 NPI:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0   Nested posted-interrupt event
 PIW:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0   Posted-interrupt wakeup event

____________________________________________

*** /proc/meminfo
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:24:49.229999985 -0300 /proc/meminfo
MemTotal:       65237620 kB
MemFree:        55694224 kB
MemAvailable:   59319124 kB
Buffers:          436644 kB
Cached:          2947096 kB
SwapCached:            0 kB
Active:          1091916 kB
Inactive:        5019372 kB
Active(anon):      16724 kB
Inactive(anon):  2899808 kB
Active(file):    1075192 kB
Inactive(file):  2119564 kB
Unevictable:          32 kB
Mlocked:              32 kB
SwapTotal:      16777212 kB
SwapFree:       16777212 kB
Zswap:                 0 kB
Zswapped:              0 kB
Dirty:               484 kB
Writeback:            24 kB
AnonPages:       2588272 kB
Mapped:           788952 kB
Shmem:            188928 kB
KReclaimable:    1149048 kB
Slab:            1324376 kB
SReclaimable:    1149048 kB
SUnreclaim:       175328 kB
KernelStack:       16088 kB
PageTables:        38044 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:    49396020 kB
Committed_AS:    9562248 kB
VmallocTotal:   34359738367 kB
VmallocUsed:      157984 kB
VmallocChunk:          0 kB
Percpu:            15552 kB
HardwareCorrupted:     0 kB
AnonHugePages:    761856 kB
ShmemHugePages:        0 kB
ShmemPmdMapped:        0 kB
FileHugePages:     61440 kB
FilePmdMapped:     45056 kB
CmaTotal:              0 kB
CmaFree:               0 kB
HugePages_Total:       0
HugePages_Free:        0
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:       2048 kB
Hugetlb:               0 kB
DirectMap4k:     2289424 kB
DirectMap2M:    11765760 kB
DirectMap1G:    52428800 kB

____________________________________________

*** /proc/modules
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:24:52.793400401 -0300 /proc/modules
rfcomm 94208 16 - Live 0xffffffffc0766000
nvidia_drm 73728 0 - Live 0xffffffffc0608000 (POE)
nvidia_modeset 1466368 1 nvidia_drm, Live 0xffffffffc1956000 (POE)
nvidia 60055552 34 nvidia_modeset, Live 0xffffffffc31a0000 (POE)
hid_logitech_hidpp 69632 0 - Live 0xffffffffc09e5000
ccm 20480 3 - Live 0xffffffffc0867000
algif_aead 16384 0 - Live 0xffffffffc08b4000
cbc 16384 0 - Live 0xffffffffc0797000
joydev 28672 0 - Live 0xffffffffc06e6000
des_generic 16384 0 - Live 0xffffffffc05fd000
libdes 24576 1 des_generic, Live 0xffffffffc09de000
ecb 16384 0 - Live 0xffffffffc091b000
algif_skcipher 16384 1 - Live 0xffffffffc08aa000
cmac 16384 3 - Live 0xffffffffc0816000
md4 16384 0 - Live 0xffffffffc07be000
algif_hash 16384 1 - Live 0xffffffffc0623000
mousedev 24576 0 - Live 0xffffffffc05eb000
bnep 32768 2 - Live 0xffffffffc0a82000
af_alg 36864 7 algif_aead,algif_skcipher,algif_hash, Live 0xffffffffc0a60000
vmw_vmci 118784 0 - Live 0xffffffffc09b9000
vboxnetflt 32768 0 - Live 0xffffffffc0930000 (OE)
vboxnetadp 28672 0 - Live 0xffffffffc062e000 (OE)
btusb 65536 0 - Live 0xffffffffc0dc4000
vboxdrv 544768 2 vboxnetflt,vboxnetadp, Live 0xffffffffc137d000 (OE)
btrtl 28672 1 btusb, Live 0xffffffffc0913000
snd_sof_amd_renoir 16384 0 - Live 0xffffffffc07b9000
pkcs8_key_parser 16384 0 - Live 0xffffffffc07ce000
btbcm 24576 1 btusb, Live 0xffffffffc07b2000
intel_rapl_msr 20480 0 - Live 0xffffffffc07ac000
snd_sof_amd_acp 53248 1 snd_sof_amd_renoir, Live 0xffffffffc079e000
intel_rapl_common 32768 1 intel_rapl_msr, Live 0xffffffffc0847000
snd_sof_pci 24576 1 snd_sof_amd_renoir, Live 0xffffffffc093e000
btintel 45056 1 btusb, Live 0xffffffffc160a000
snd_hda_codec_realtek 167936 1 - Live 0xffffffffc113f000
btmtk 16384 1 btusb, Live 0xffffffffc0761000
snd_sof 307200 3 snd_sof_amd_renoir,snd_sof_amd_acp,snd_sof_pci, Live 0xffffffffc124e000
asus_nb_wmi 28672 0 - Live 0xffffffffc0de5000
iwlmvm 524288 0 - Live 0xffffffffc10be000
snd_hda_codec_generic 98304 1 snd_hda_codec_realtek, Live 0xffffffffc0df3000
asus_wmi 65536 1 asus_nb_wmi, Live 0xffffffffc0946000
edac_mce_amd 57344 0 - Live 0xffffffffc0921000
snd_hda_codec_hdmi 86016 2 - Live 0xffffffffc10a8000
ledtrig_audio 16384 2 snd_hda_codec_generic,asus_wmi, Live 0xffffffffc0694000
snd_sof_utils 20480 1 snd_sof, Live 0xffffffffc068e000
bluetooth 937984 44 rfcomm,bnep,btusb,btrtl,btbcm,btintel,btmtk, Live 0xffffffffc1524000
snd_soc_core 393216 1 snd_sof, Live 0xffffffffc12b9000
hid_logitech_dj 36864 0 - Live 0xffffffffc0b78000
hid_multitouch 32768 0 - Live 0xffffffffc08e4000
kvm_amd 172032 0 - Live 0xffffffffc0d58000
snd_hda_intel 61440 5 - Live 0xffffffffc089a000
sparse_keymap 16384 1 asus_wmi, Live 0xffffffffc064c000
ecdh_generic 16384 2 bluetooth, Live 0xffffffffc074a000
mac80211 1298432 1 iwlmvm, Live 0xffffffffc3062000
platform_profile 16384 1 asus_wmi, Live 0xffffffffc0735000
wmi_bmof 16384 0 - Live 0xffffffffc06bd000
amdgpu 10240000 20 - Live 0xffffffffc2546000
snd_intel_dspcfg 36864 2 snd_sof,snd_hda_intel, Live 0xffffffffc0757000
snd_compress 28672 1 snd_soc_core, Live 0xffffffffc06de000
ac97_bus 16384 1 snd_soc_core, Live 0xffffffffc05e1000
snd_intel_sdw_acpi 20480 1 snd_intel_dspcfg, Live 0xffffffffc05db000
libarc4 16384 1 mac80211, Live 0xffffffffc0603000
snd_pcm_dmaengine 16384 1 snd_soc_core, Live 0xffffffffc063c000
kvm 1138688 1 kvm_amd, Live 0xffffffffc0f66000
uvcvideo 163840 0 - Live 0xffffffffc0f3d000
snd_rpl_pci_acp6x 20480 0 - Live 0xffffffffc06d8000
snd_hda_codec 188416 4 snd_hda_codec_realtek,snd_hda_codec_generic,snd_hda_codec_hdmi,snd_hda_intel, Live 0xffffffffc0edf000
iwlwifi 491520 1 iwlmvm, Live 0xffffffffc0e66000
snd_acp_pci 16384 0 - Live 0xffffffffc0730000
gpu_sched 49152 1 amdgpu, Live 0xffffffffc07e5000
snd_pci_acp6x 20480 0 - Live 0xffffffffc0705000
irqbypass 16384 1 kvm, Live 0xffffffffc06b8000
videobuf2_vmalloc 20480 1 uvcvideo, Live 0xffffffffc07c8000
snd_pci_acp5x 20480 0 - Live 0xffffffffc067b000
drm_buddy 20480 1 amdgpu, Live 0xffffffffc080b000
crct10dif_pclmul 16384 1 - Live 0xffffffffc05e6000
videobuf2_memops 20480 1 videobuf2_vmalloc, Live 0xffffffffc0578000
snd_hda_core 118784 5 snd_hda_codec_realtek,snd_hda_codec_generic,snd_hda_codec_hdmi,snd_hda_intel,snd_hda_codec, Live 0xffffffffc099b000
crc32_pclmul 16384 0 - Live 0xffffffffc0637000
videobuf2_v4l2 40960 1 uvcvideo, Live 0xffffffffc0e57000
drm_ttm_helper 16384 1 amdgpu, Live 0xffffffffc0e52000
r8169 102400 0 - Live 0xffffffffc0e0f000
polyval_clmulni 16384 0 - Live 0xffffffffc0de0000
snd_hwdep 16384 1 snd_hda_codec, Live 0xffffffffc0c1e000
usbhid 73728 1 hid_logitech_dj, Live 0xffffffffc0c03000
tpm_crb 20480 0 - Live 0xffffffffc0bb8000
videobuf2_common 86016 4 uvcvideo,videobuf2_vmalloc,videobuf2_memops,videobuf2_v4l2, Live 0xffffffffc0d95000
snd_rn_pci_acp3x 24576 0 - Live 0xffffffffc08b9000
polyval_generic 16384 1 polyval_clmulni, Live 0xffffffffc0710000
cfg80211 1118208 3 iwlmvm,mac80211,iwlwifi, Live 0xffffffffc0c46000
ttm 94208 2 amdgpu,drm_ttm_helper, Live 0xffffffffc0c2e000
snd_pcm 172032 11 snd_sof_amd_acp,snd_sof,snd_hda_codec_hdmi,snd_sof_utils,snd_soc_core,snd_hda_intel,snd_compress,snd_pcm_dmaengine,snd_hda_codec,snd_pci_acp6x,snd_hda_core, Live 0xffffffffc0bd8000
gf128mul 16384 1 polyval_generic, Live 0xffffffffc0b63000
ucsi_acpi 16384 0 - Live 0xffffffffc0b73000
snd_acp_config 16384 3 snd_sof_amd_renoir,snd_acp_pci,snd_rn_pci_acp3x, Live 0xffffffffc0a7d000
ghash_clmulni_intel 16384 0 - Live 0xffffffffc0bd3000
realtek 36864 1 - Live 0xffffffffc0b54000
videodev 315392 3 uvcvideo,videobuf2_v4l2,videobuf2_common, Live 0xffffffffc0af0000
sp5100_tco 20480 0 - Live 0xffffffffc0ae5000
drm_display_helper 180224 1 amdgpu, Live 0xffffffffc0aa8000
typec_ucsi 53248 1 ucsi_acpi, Live 0xffffffffc0a6f000
snd_soc_acpi 16384 2 snd_sof_amd_renoir,snd_acp_config, Live 0xffffffffc070b000
snd_timer 49152 1 snd_pcm, Live 0xffffffffc06f8000
vfat 24576 1 - Live 0xffffffffc06f1000
tpm_tis 16384 0 - Live 0xffffffffc05b8000
mdio_devres 16384 1 r8169, Live 0xffffffffc05b3000
aesni_intel 393216 6 - Live 0xffffffffc09ff000
crypto_simd 16384 1 aesni_intel, Live 0xffffffffc03c8000
fat 98304 1 vfat, Live 0xffffffffc0982000
cryptd 24576 3 ghash_clmulni_intel,crypto_simd, Live 0xffffffffc0750000
rapl 16384 0 - Live 0xffffffffc06d3000
mc 73728 4 uvcvideo,videobuf2_v4l2,videobuf2_common,videodev, Live 0xffffffffc06a5000
snd 126976 21 snd_hda_codec_realtek,snd_sof,snd_hda_codec_generic,snd_hda_codec_hdmi,snd_soc_core,snd_hda_intel,snd_compress,snd_hda_codec,snd_hwdep,snd_pcm,snd_timer, Live 0xffffffffc0657000
pcspkr 16384 0 - Live 0xffffffffc08f0000
typec 90112 1 typec_ucsi, Live 0xffffffffc08cd000
tpm_tis_core 36864 1 tpm_tis, Live 0xffffffffc08c3000
soundcore 16384 1 snd, Live 0xffffffffc08af000
libphy 172032 3 r8169,realtek,mdio_devres, Live 0xffffffffc086f000
cec 81920 1 drm_display_helper, Live 0xffffffffc0852000
ccp 135168 1 kvm_amd, Live 0xffffffffc0825000
snd_pci_acp3x 20480 0 - Live 0xffffffffc081b000
k10temp 16384 0 - Live 0xffffffffc0811000
i2c_piix4 36864 0 - Live 0xffffffffc0801000
rfkill 32768 11 iwlmvm,asus_wmi,bluetooth,cfg80211, Live 0xffffffffc07f2000
mac_hid 16384 0 - Live 0xffffffffc07e0000
roles 16384 1 typec_ucsi, Live 0xffffffffc07c3000
wmi 45056 2 asus_wmi,wmi_bmof, Live 0xffffffffc078b000
video 61440 1 asus_wmi, Live 0xffffffffc073a000
tpm 102400 3 tpm_crb,tpm_tis,tpm_tis_core, Live 0xffffffffc0716000
i2c_hid_acpi 16384 0 - Live 0xffffffffc06c3000
asus_wireless 20480 0 - Live 0xffffffffc069b000
i2c_hid 40960 1 i2c_hid_acpi, Live 0xffffffffc0641000
amd_pmc 32768 0 - Live 0xffffffffc05d2000
rng_core 20480 2 ccp,tpm, Live 0xffffffffc05ad000
acpi_cpufreq 32768 0 - Live 0xffffffffc055f000
dm_multipath 45056 0 - Live 0xffffffffc05bd000
dm_mod 188416 1 dm_multipath, Live 0xffffffffc057e000
sg 49152 0 - Live 0xffffffffc056b000
crypto_user 24576 0 - Live 0xffffffffc03d7000
fuse 176128 5 - Live 0xffffffffc0533000
bpf_preload 24576 0 - Live 0xffffffffc052c000
ip_tables 36864 0 - Live 0xffffffffc03df000
x_tables 57344 1 ip_tables, Live 0xffffffffc0382000
ext4 1015808 2 - Live 0xffffffffc0433000
crc32c_generic 16384 0 - Live 0xffffffffc03d2000
crc16 16384 2 bluetooth,ext4, Live 0xffffffffc03cd000
mbcache 16384 1 ext4, Live 0xffffffffc0374000
jbd2 188416 1 ext4, Live 0xffffffffc0404000
serio_raw 20480 0 - Live 0xffffffffc037c000
atkbd 36864 0 - Live 0xffffffffc036a000
libps2 20480 1 atkbd, Live 0xffffffffc0364000
vivaldi_fmap 16384 1 atkbd, Live 0xffffffffc0333000
nvme 61440 4 - Live 0xffffffffc03f4000
nvme_core 208896 6 nvme, Live 0xffffffffc0394000
xhci_pci 20480 0 - Live 0xffffffffc03e9000
crc32c_intel 24576 4 - Live 0xffffffffc0343000
i8042 49152 1 asus_nb_wmi, Live 0xffffffffc0357000
xhci_pci_renesas 24576 1 xhci_pci, Live 0xffffffffc034d000
nvme_common 24576 1 nvme_core, Live 0xffffffffc0339000
serio 28672 4 serio_raw,atkbd,i8042, Live 0xffffffffc032b000

____________________________________________

*** /proc/version
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:28:29.525346983 -0300 /proc/version
Linux version 6.0.1-arch2-1 (linux@archlinux) (gcc (GCC) 12.2.0, GNU ld (GNU Binutils) 2.39.0) #1 SMP PREEMPT_DYNAMIC Thu, 13 Oct 2022 18:58:49 +0000

____________________________________________

*** /proc/pci does not exist

____________________________________________

*** /proc/iomem
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:48:26.834765607 -0300 /proc/iomem
00000000-00000fff : Reserved
00001000-0009ffff : System RAM
000a0000-000fffff : Reserved
  00000000-00000000 : PCI Bus 0000:00
  000a0000-000dffff : PCI Bus 0000:00
  000f0000-000fffff : System ROM
00100000-09bfefff : System RAM
09bff000-0a000fff : Reserved
0a001000-0a1fffff : System RAM
0a200000-0a20efff : ACPI Non-volatile Storage
0a20f000-df1ac017 : System RAM
df1ac018-df1b9857 : System RAM
df1b9858-df1ba017 : System RAM
df1ba018-df1c9e57 : System RAM
df1c9e58-e7d71fff : System RAM
e7d72000-e7da0fff : Reserved
e7da1000-e9a45fff : System RAM
e9a46000-e9a46fff : Reserved
e9a47000-eaed3fff : System RAM
eaed4000-ec3eefff : Reserved
  ec3cd000-ec3d0fff : MSFT0101:00
    ec3cd000-ec3d0fff : MSFT0101:00
  ec3d1000-ec3d4fff : MSFT0101:00
    ec3d1000-ec3d4fff : MSFT0101:00
ec3ef000-ec44efff : ACPI Tables
ec44f000-ec782fff : ACPI Non-volatile Storage
  ec781ca6-ec782ca5 : USBC000:00
ec783000-ecffefff : Reserved
ecfff000-edffffff : System RAM
ee000000-fcffffff : Reserved
  f0000000-fcffffff : PCI Bus 0000:00
    f0000000-f7ffffff : PCI MMCONFIG 0000 [bus 00-7f]
      f0000000-f7ffffff : pnp 00:00
    fb000000-fc0fffff : PCI Bus 0000:01
      fb000000-fbffffff : 0000:01:00.0
        fb000000-fbffffff : nvidia
      fc000000-fc07ffff : 0000:01:00.0
      fc080000-fc083fff : 0000:01:00.1
        fc080000-fc083fff : ICH HD audio
    fc200000-fc5fffff : PCI Bus 0000:06
      fc200000-fc2fffff : 0000:06:00.4
        fc200000-fc2fffff : xhci-hcd
      fc300000-fc3fffff : 0000:06:00.3
        fc300000-fc3fffff : xhci-hcd
      fc400000-fc4fffff : 0000:06:00.2
        fc400000-fc4fffff : ccp
      fc500000-fc57ffff : 0000:06:00.0
      fc580000-fc5bffff : 0000:06:00.5
      fc5c0000-fc5c7fff : 0000:06:00.6
        fc5c0000-fc5c7fff : ICH HD audio
      fc5c8000-fc5cbfff : 0000:06:00.1
        fc5c8000-fc5cbfff : ICH HD audio
      fc5cc000-fc5cdfff : 0000:06:00.2
        fc5cc000-fc5cdfff : ccp
    fc600000-fc6fffff : PCI Bus 0000:05
      fc600000-fc603fff : 0000:05:00.0
        fc600000-fc603fff : nvme
    fc700000-fc7fffff : PCI Bus 0000:04
      fc700000-fc703fff : 0000:04:00.0
        fc700000-fc703fff : nvme
    fc800000-fc8fffff : PCI Bus 0000:03
      fc800000-fc803fff : 0000:03:00.0
        fc800000-fc803fff : iwlwifi
    fc900000-fc9fffff : PCI Bus 0000:02
      fc900000-fc903fff : 0000:02:00.0
      fc904000-fc904fff : 0000:02:00.0
        fc904000-fc904fff : r8169
fd000000-fdffffff : Reserved
  fd210510-fd21053f : MSFT0101:00
  fd300000-fd37ffff : amd_iommu
feb00000-feb00007 : SB800 TCO
feb80000-fec01fff : Reserved
  fec00000-fec003ff : IOAPIC 0
  fec01000-fec013ff : IOAPIC 1
fec10000-fec10fff : Reserved
  fec10000-fec10fff : pnp 00:03
fed00000-fed00fff : Reserved
  fed00000-fed003ff : HPET 0
    fed00000-fed003ff : PNP0103:00
fed40000-fed44fff : Reserved
fed80000-fed8ffff : Reserved
  fed81200-fed812ff : AMDI0030:00
  fed81500-fed818ff : AMDI0030:00
    fed81500-fed818ff : AMDI0030:00 AMDI0030:00
fedc0000-fedc0fff : pnp 00:03
fedc4000-fedc9fff : Reserved
  fedc5000-fedc5fff : AMDI0010:03
    fedc5000-fedc5fff : AMDI0010:03 AMDI0010:03
fedcc000-fedcefff : Reserved
fedd5000-fedd5fff : Reserved
fee00000-fee00fff : Local APIC
  fee00000-fee00fff : pnp 00:03
ff000000-ffffffff : Reserved
  ff000000-ffffffff : pnp 00:03
100000000-fee2fffff : System RAM
  62fe00000-630c01d4b : Kernel code
  630e00000-63190dfff : Kernel rodata
  631a00000-631c078bf : Kernel data
  632289000-6325fffff : Kernel bss
fee300000-100fffffff : Reserved
1010000000-ffffffffff : PCI Bus 0000:00
  fc00000000-fe01ffffff : PCI Bus 0000:01
    fc00000000-fdffffffff : 0000:01:00.0
    fe00000000-fe01ffffff : 0000:01:00.0
  fe10000000-fe201fffff : PCI Bus 0000:06
    fe10000000-fe1fffffff : 0000:06:00.0
    fe20000000-fe201fffff : 0000:06:00.0
3fffe0000000-3fffffffffff : 0000:06:00.0

____________________________________________

*** /proc/mtrr
*** ls: -rw-r--r-- 1 root root 0 2022-10-27 20:48:26.834765607 -0300 /proc/mtrr
reg00: base=0x000000000 (    0MB), size= 2048MB, count=1: write-back
reg01: base=0x080000000 ( 2048MB), size= 1024MB, count=1: write-back
reg02: base=0x0c0000000 ( 3072MB), size=  512MB, count=1: write-back
reg03: base=0x0e0000000 ( 3584MB), size=  256MB, count=1: write-back

____________________________________________

*** /proc/driver/nvidia/./version
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:48:31.541007107 -0300 /proc/driver/nvidia/./version
NVRM version: NVIDIA UNIX x86_64 Kernel Module  520.56.06  Thu Oct  6 21:38:55 UTC 2022
GCC version:  gcc version 12.2.0 (GCC) 

____________________________________________

*** /proc/driver/nvidia/./gpus/0000:01:00.0/information
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:24:54.216733767 -0300 /proc/driver/nvidia/./gpus/0000:01:00.0/information
Model: 		 NVIDIA GeForce RTX 3060 Laptop GPU
IRQ:   		 114
GPU UUID: 	 GPU-fceee73c-fd00-9cc3-fead-6d6ab3715614
Video BIOS: 	 94.06.17.00.5f
Bus Type: 	 PCIe
DMA Size: 	 47 bits
DMA Mask: 	 0x7fffffffffff
Bus Location: 	 0000:01:00.0
Device Minor: 	 0
GPU Excluded:	 No

____________________________________________

*** /proc/driver/nvidia/./gpus/0000:01:00.0/registry
*** ls: -rw-r--r-- 1 root root 0 2022-10-27 20:48:33.974169298 -0300 /proc/driver/nvidia/./gpus/0000:01:00.0/registry
Binary: ""

____________________________________________

*** /proc/driver/nvidia/./warnings/README
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:48:32.497602827 -0300 /proc/driver/nvidia/./warnings/README
The NVIDIA graphics driver tries to detect potential problems
with the host system and warns about them using the system's
logging mechanisms. Important warning message are also logged
to dedicated text files in this directory.

____________________________________________

*** /proc/driver/nvidia/./params
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:24:54.216733767 -0300 /proc/driver/nvidia/./params
ResmanDebugLevel: 4294967295
RmLogonRC: 1
ModifyDeviceFiles: 1
DeviceFileUID: 0
DeviceFileGID: 0
DeviceFileMode: 438
InitializeSystemMemoryAllocations: 1
UsePageAttributeTable: 4294967295
EnableMSI: 1
EnablePCIeGen3: 0
MemoryPoolSize: 0
KMallocHeapMaxSize: 0
VMallocHeapMaxSize: 0
IgnoreMMIOCheck: 0
TCEBypassMode: 0
EnableStreamMemOPs: 0
EnableUserNUMAManagement: 1
NvLinkDisable: 0
RmProfilingAdminOnly: 1
PreserveVideoMemoryAllocations: 0
EnableS0ixPowerManagement: 0
S0ixPowerManagementVideoMemoryThreshold: 256
DynamicPowerManagement: 3
DynamicPowerManagementVideoMemoryThreshold: 200
RegisterPCIDriver: 1
EnablePCIERelaxedOrderingMode: 0
EnableGpuFirmware: 18
EnableGpuFirmwareLogs: 2
EnableDbgBreakpoint: 0
OpenRmEnableUnsupportedGpus: 0
DmaRemapPeerMmio: 1
RegistryDwords: ""
RegistryDwordsPerDevice: ""
RmMsg: ""
GpuBlacklist: ""
TemporaryFilePath: ""
ExcludedGpus: ""

____________________________________________

*** /proc/driver/nvidia/./registry
*** ls: -rw-r--r-- 1 root root 0 2022-10-27 20:48:31.541007107 -0300 /proc/driver/nvidia/./registry
Binary: ""

____________________________________________

*** /proc/asound/cards
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:48:31.331023287 -0300 /proc/asound/cards
 0 [Generic        ]: HDA-Intel - HD-Audio Generic
                      HD-Audio Generic at 0xfc5c8000 irq 110
 1 [Generic_1      ]: HDA-Intel - HD-Audio Generic
                      HD-Audio Generic at 0xfc5c0000 irq 111
 2 [NVidia         ]: HDA-Intel - HDA NVidia
                      HDA NVidia at 0xfc080000 irq 112

____________________________________________

*** /proc/asound/pcm
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:48:31.331023287 -0300 /proc/asound/pcm
00-03: HDMI 0 : HDMI 0 : playback 1
01-00: ALC256 Analog : ALC256 Analog : playback 1 : capture 1
02-03: HDMI 0 : HDMI 0 : playback 1
02-07: HDMI 1 : HDMI 1 : playback 1
02-08: HDMI 2 : HDMI 2 : playback 1
02-09: HDMI 3 : HDMI 3 : playback 1

____________________________________________

*** /proc/asound/modules
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:48:31.331023287 -0300 /proc/asound/modules
 0 snd_hda_intel
 1 snd_hda_intel
 2 snd_hda_intel

____________________________________________

*** /proc/asound/devices
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:48:31.331023287 -0300 /proc/asound/devices
  2: [ 0- 3]: digital audio playback
  3: [ 0- 0]: hardware dependent
  4: [ 1- 0]: digital audio playback
  5: [ 1- 0]: digital audio capture
  6: [ 1- 0]: hardware dependent
  7: [ 0]   : control
  8: [ 1]   : control
  9: [ 2- 3]: digital audio playback
 10: [ 2- 7]: digital audio playback
 11: [ 2- 8]: digital audio playback
 12: [ 2- 9]: digital audio playback
 13: [ 2- 0]: hardware dependent
 14: [ 2]   : control
 33:        : timer

____________________________________________

*** /proc/asound/version
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:48:31.331023287 -0300 /proc/asound/version
Advanced Linux Sound Architecture Driver Version k6.0.1-arch2-1.

____________________________________________

*** /proc/asound/timers
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:48:31.331023287 -0300 /proc/asound/timers
G0: system timer : 3333.333us (10000000 ticks)
P0-3-0: PCM playback 0-3-0 : SLAVE
P1-0-0: PCM playback 1-0-0 : SLAVE
P1-0-1: PCM capture 1-0-1 : SLAVE
P2-3-0: PCM playback 2-3-0 : SLAVE
P2-7-0: PCM playback 2-7-0 : SLAVE
P2-8-0: PCM playback 2-8-0 : SLAVE
P2-9-0: PCM playback 2-9-0 : SLAVE

____________________________________________

*** /proc/asound/hwdep
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:48:31.331023287 -0300 /proc/asound/hwdep
00-00: HDA Codec 0
01-00: HDA Codec 0
02-00: HDA Codec 0

____________________________________________

*** /proc/asound/card0/codec#0
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:48:31.594336331 -0300 /proc/asound/card0/codec#0
Codec: ATI R6xx HDMI
Address: 0
AFG Function Id: 0x1 (unsol 0)
Vendor Id: 0x1002aa01
Subsystem Id: 0x00aa0100
Revision Id: 0x100700
No Modem Function Group found
Default PCM:
    rates [0x70]: 32000 44100 48000
    bits [0x2]: 16
    formats [0x1]: PCM
Default Amp-In caps: N/A
Default Amp-Out caps: N/A
State of AFG node 0x01:
  Power states:  D0 D3 CLKSTOP EPSS
  Power: setting=D0, actual=D0, Clock-stop-OK
GPIO: io=0, o=0, i=0, unsolicited=0, wake=0
Node 0x02 [Audio Output] wcaps 0x221: Stereo Digital Stripe
  Converter: stream=0, channel=0
  Digital: Enabled GenLevel
  Digital category: 0x2
  IEC Coding Type: 0x0
Node 0x03 [Pin Complex] wcaps 0x400381: Stereo Digital
  Control: name="IEC958 Playback Con Mask", index=0, device=0
  Control: name="IEC958 Playback Pro Mask", index=0, device=0
  Control: name="IEC958 Playback Default", index=0, device=0
  Control: name="IEC958 Playback Switch", index=0, device=0
  Pincap 0x00000094: OUT Detect HDMI
  Pin Default 0x185600f0: [Jack] Digital Out at Int HDMI
    Conn = Digital, Color = Unknown
    DefAssociation = 0xf, Sequence = 0x0
  Pin-ctls: 0x40: OUT
  Unsolicited: tag=00, enabled=0
  Connection: 1
     0x02
Node 0x04 [Audio Output] wcaps 0x221: Stereo Digital Stripe
  Converter: stream=0, channel=0
  Digital:
  Digital category: 0x0
  IEC Coding Type: 0x0
Node 0x05 [Pin Complex] wcaps 0x400381: Stereo Digital
  Pincap 0x00000094: OUT Detect HDMI
  Pin Default 0x585600f0: [N/A] Digital Out at Int HDMI
    Conn = Digital, Color = Unknown
    DefAssociation = 0xf, Sequence = 0x0
  Pin-ctls: 0x40: OUT
  Unsolicited: tag=00, enabled=0
  Connection: 1
     0x04
Node 0x06 [Audio Output] wcaps 0x221: Stereo Digital Stripe
  Converter: stream=0, channel=0
  Digital:
  Digital category: 0x0
  IEC Coding Type: 0x0
Node 0x07 [Pin Complex] wcaps 0x400381: Stereo Digital
  Pincap 0x00000094: OUT Detect HDMI
  Pin Default 0x585600f0: [N/A] Digital Out at Int HDMI
    Conn = Digital, Color = Unknown
    DefAssociation = 0xf, Sequence = 0x0
  Pin-ctls: 0x40: OUT
  Unsolicited: tag=00, enabled=0
  Connection: 1
     0x06
Node 0x08 [Audio Output] wcaps 0x221: Stereo Digital Stripe
  Converter: stream=0, channel=0
  Digital:
  Digital category: 0x0
  IEC Coding Type: 0x0
Node 0x09 [Pin Complex] wcaps 0x400381: Stereo Digital
  Pincap 0x00000094: OUT Detect HDMI
  Pin Default 0x585600f0: [N/A] Digital Out at Int HDMI
    Conn = Digital, Color = Unknown
    DefAssociation = 0xf, Sequence = 0x0
  Pin-ctls: 0x40: OUT
  Unsolicited: tag=00, enabled=0
  Connection: 1
     0x08
Node 0x0a [Audio Output] wcaps 0x221: Stereo Digital Stripe
  Converter: stream=0, channel=0
  Digital:
  Digital category: 0x0
  IEC Coding Type: 0x0
Node 0x0b [Pin Complex] wcaps 0x400381: Stereo Digital
  Pincap 0x00000094: OUT Detect HDMI
  Pin Default 0x585600f0: [N/A] Digital Out at Int HDMI
    Conn = Digital, Color = Unknown
    DefAssociation = 0xf, Sequence = 0x0
  Pin-ctls: 0x40: OUT
  Unsolicited: tag=00, enabled=0
  Connection: 1
     0x0a
Node 0x0c [Audio Output] wcaps 0x221: Stereo Digital Stripe
  Converter: stream=0, channel=0
  Digital:
  Digital category: 0x0
  IEC Coding Type: 0x0
Node 0x0d [Pin Complex] wcaps 0x400381: Stereo Digital
  Pincap 0x00000094: OUT Detect HDMI
  Pin Default 0x585600f0: [N/A] Digital Out at Int HDMI
    Conn = Digital, Color = Unknown
    DefAssociation = 0xf, Sequence = 0x0
  Pin-ctls: 0x40: OUT
  Unsolicited: tag=00, enabled=0
  Connection: 1
     0x0c

____________________________________________

*** /proc/asound/card0/eld#0.0
*** ls: -rw-r--r-- 1 root root 0 2022-10-27 20:48:31.594336331 -0300 /proc/asound/card0/eld#0.0
monitor_present		1
eld_valid		1
monitor_name		U28E590
connection_type		HDMI
eld_version		[0x2] CEA-861D or below
edid_version		[0x3] CEA-861-B, C or D
manufacture_id		0x2d4c
product_id		0xc4e
port_id			0x0
support_hdcp		0
support_ai		1
audio_sync_delay	0
speakers		[0x1] FL/FR
sad_count		1
sad0_coding_type	[0x1] LPCM
sad0_channels		2
sad0_rates		[0xe0] 32000 44100 48000
sad0_bits		[0xe0000] 16 20 24

____________________________________________

*** /proc/asound/card1/codec#0
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:48:31.594336331 -0300 /proc/asound/card1/codec#0
Codec: Realtek ALC256
Address: 0
AFG Function Id: 0x1 (unsol 1)
Vendor Id: 0x10ec0256
Subsystem Id: 0x10431682
Revision Id: 0x100002
No Modem Function Group found
Default PCM:
    rates [0x560]: 44100 48000 96000 192000
    bits [0xe]: 16 20 24
    formats [0x1]: PCM
Default Amp-In caps: N/A
Default Amp-Out caps: N/A
State of AFG node 0x01:
  Power states:  D0 D1 D2 D3 D3cold CLKSTOP EPSS
  Power: setting=D0, actual=D0
GPIO: io=3, o=0, i=0, unsolicited=1, wake=0
  IO[0]: enable=0, dir=0, wake=0, sticky=0, data=0, unsol=0
  IO[1]: enable=0, dir=0, wake=0, sticky=0, data=0, unsol=0
  IO[2]: enable=0, dir=0, wake=0, sticky=0, data=0, unsol=0
Node 0x02 [Audio Output] wcaps 0x41d: Stereo Amp-Out
  Control: name="Speaker Playback Volume", index=0, device=0
    ControlAmp: chs=3, dir=Out, idx=0, ofs=0
  Amp-Out caps: ofs=0x57, nsteps=0x57, stepsize=0x02, mute=0
  Amp-Out vals:  [0x57 0x57]
  Converter: stream=0, channel=0
  PCM:
    rates [0x560]: 44100 48000 96000 192000
    bits [0xe]: 16 20 24
    formats [0x1]: PCM
  Power states:  D0 D1 D2 D3 EPSS
  Power: setting=D0, actual=D0
Node 0x03 [Audio Output] wcaps 0x41d: Stereo Amp-Out
  Control: name="Headphone Playback Volume", index=0, device=0
    ControlAmp: chs=3, dir=Out, idx=0, ofs=0
  Device: name="ALC256 Analog", type="Audio", device=0
  Amp-Out caps: ofs=0x57, nsteps=0x57, stepsize=0x02, mute=0
  Amp-Out vals:  [0x00 0x00]
  Converter: stream=0, channel=0
  PCM:
    rates [0x560]: 44100 48000 96000 192000
    bits [0xe]: 16 20 24
    formats [0x1]: PCM
  Power states:  D0 D1 D2 D3 EPSS
  Power: setting=D0, actual=D0
Node 0x04 [Vendor Defined Widget] wcaps 0xf00000: Mono
Node 0x05 [Vendor Defined Widget] wcaps 0xf00000: Mono
Node 0x06 [Audio Output] wcaps 0x611: Stereo Digital
  Converter: stream=0, channel=0
  Digital:
  Digital category: 0x0
  IEC Coding Type: 0x0
  PCM:
    rates [0x5e0]: 44100 48000 88200 96000 192000
    bits [0xe]: 16 20 24
    formats [0x1]: PCM
  Power states:  D0 D1 D2 D3 EPSS
  Power: setting=D0, actual=D0
Node 0x07 [Audio Input] wcaps 0x10051b: Stereo Amp-In
  Amp-In caps: ofs=0x17, nsteps=0x3f, stepsize=0x02, mute=1
  Amp-In vals:  [0x97 0x97]
  Converter: stream=0, channel=0
  SDI-Select: 0
  PCM:
    rates [0x560]: 44100 48000 96000 192000
    bits [0xe]: 16 20 24
    formats [0x1]: PCM
  Power states:  D0 D1 D2 D3 EPSS
  Power: setting=D0, actual=D0
  Connection: 1
     0x24
Node 0x08 [Audio Input] wcaps 0x10051b: Stereo Amp-In
  Control: name="Capture Volume", index=0, device=0
    ControlAmp: chs=3, dir=In, idx=0, ofs=0
  Control: name="Capture Switch", index=0, device=0
    ControlAmp: chs=3, dir=In, idx=0, ofs=0
  Device: name="ALC256 Analog", type="Audio", device=0
  Amp-In caps: ofs=0x17, nsteps=0x3f, stepsize=0x02, mute=1
  Amp-In vals:  [0x3f 0x3f]
  Converter: stream=0, channel=0
  SDI-Select: 0
  PCM:
    rates [0x560]: 44100 48000 96000 192000
    bits [0xe]: 16 20 24
    formats [0x1]: PCM
  Power states:  D0 D1 D2 D3 EPSS
  Power: setting=D0, actual=D0
  Connection: 1
     0x23
Node 0x09 [Audio Input] wcaps 0x10051b: Stereo Amp-In
  Amp-In caps: ofs=0x17, nsteps=0x3f, stepsize=0x02, mute=1
  Amp-In vals:  [0x97 0x97]
  Converter: stream=0, channel=0
  SDI-Select: 0
  PCM:
    rates [0x560]: 44100 48000 96000 192000
    bits [0xe]: 16 20 24
    formats [0x1]: PCM
  Power states:  D0 D1 D2 D3 EPSS
  Power: setting=D0, actual=D0
  Connection: 1
     0x22
Node 0x0a [Vendor Defined Widget] wcaps 0xf00000: Mono
Node 0x0b [Vendor Defined Widget] wcaps 0xf00000: Mono
Node 0x0c [Vendor Defined Widget] wcaps 0xf00000: Mono
Node 0x0d [Vendor Defined Widget] wcaps 0xf00000: Mono
Node 0x0e [Vendor Defined Widget] wcaps 0xf00000: Mono
Node 0x0f [Vendor Defined Widget] wcaps 0xf00000: Mono
Node 0x10 [Vendor Defined Widget] wcaps 0xf00000: Mono
Node 0x11 [Vendor Defined Widget] wcaps 0xf00000: Mono
Node 0x12 [Pin Complex] wcaps 0x40040b: Stereo Amp-In
  Control: name="Internal Mic Boost Volume", index=0, device=0
    ControlAmp: chs=3, dir=In, idx=0, ofs=0
  Amp-In caps: ofs=0x00, nsteps=0x03, stepsize=0x27, mute=0
  Amp-In vals:  [0x02 0x02]
  Pincap 0x00000020: IN
  Pin Default 0x90a60130: [Fixed] Mic at Int N/A
    Conn = Digital, Color = Unknown
    DefAssociation = 0x3, Sequence = 0x0
    Misc = NO_PRESENCE
  Pin-ctls: 0x20: IN
  Power states:  D0 D1 D2 D3 EPSS
  Power: setting=D0, actual=D0
Node 0x13 [Pin Complex] wcaps 0x40040b: Stereo Amp-In
  Amp-In caps: ofs=0x00, nsteps=0x03, stepsize=0x27, mute=0
  Amp-In vals:  [0x00 0x00]
  Pincap 0x00000020: IN
  Pin Default 0x40000000: [N/A] Line Out at Ext N/A
    Conn = Unknown, Color = Unknown
    DefAssociation = 0x0, Sequence = 0x0
  Pin-ctls: 0x00:
  Power states:  D0 D1 D2 D3 EPSS
  Power: setting=D0, actual=D0
Node 0x14 [Pin Complex] wcaps 0x40058d: Stereo Amp-Out
  Control: name="Speaker Playback Switch", index=0, device=0
    ControlAmp: chs=3, dir=Out, idx=0, ofs=0
  Amp-Out caps: ofs=0x00, nsteps=0x00, stepsize=0x00, mute=1
  Amp-Out vals:  [0x00 0x00]
  Pincap 0x00010014: OUT EAPD Detect
  EAPD 0x2: EAPD
  Pin Default 0x90170110: [Fixed] Speaker at Int N/A
    Conn = Analog, Color = Unknown
    DefAssociation = 0x1, Sequence = 0x0
    Misc = NO_PRESENCE
  Pin-ctls: 0x40: OUT
  Unsolicited: tag=00, enabled=0
  Power states:  D0 D1 D2 D3 EPSS
  Power: setting=D0, actual=D0
  Connection: 1
     0x02
Node 0x15 [Vendor Defined Widget] wcaps 0xf00000: Mono
Node 0x16 [Vendor Defined Widget] wcaps 0xf00000: Mono
Node 0x17 [Vendor Defined Widget] wcaps 0xf00000: Mono
Node 0x18 [Pin Complex] wcaps 0x40048b: Stereo Amp-In
  Amp-In caps: ofs=0x00, nsteps=0x03, stepsize=0x27, mute=0
  Amp-In vals:  [0x00 0x00]
  Pincap 0x00003724: IN Detect
    Vref caps: HIZ 50 GRD 80 100
  Pin Default 0x411111f0: [N/A] Speaker at Ext Rear
    Conn = 1/8, Color = Black
    DefAssociation = 0xf, Sequence = 0x0
    Misc = NO_PRESENCE
  Pin-ctls: 0x20: IN VREF_HIZ
  Unsolicited: tag=00, enabled=0
  Power states:  D0 D1 D2 D3 EPSS
  Power: setting=D0, actual=D0
Node 0x19 [Pin Complex] wcaps 0x40048b: Stereo Amp-In
  Control: name="Headset Mic Boost Volume", index=0, device=0
    ControlAmp: chs=3, dir=In, idx=0, ofs=0
  Amp-In caps: ofs=0x00, nsteps=0x03, stepsize=0x27, mute=0
  Amp-In vals:  [0x00 0x00]
  Pincap 0x00003724: IN Detect
    Vref caps: HIZ 50 GRD 80 100
  Pin Default 0x411111f0: [N/A] Speaker at Ext Rear
    Conn = 1/8, Color = Black
    DefAssociation = 0xf, Sequence = 0x0
    Misc = NO_PRESENCE
  Pin-ctls: 0x24: IN VREF_80
  Unsolicited: tag=00, enabled=0
  Power states:  D0 D1 D2 D3 EPSS
  Power: setting=D0, actual=D0
Node 0x1a [Pin Complex] wcaps 0x40048b: Stereo Amp-In
  Amp-In caps: ofs=0x00, nsteps=0x03, stepsize=0x27, mute=0
  Amp-In vals:  [0x00 0x00]
  Pincap 0x00003724: IN Detect
    Vref caps: HIZ 50 GRD 80 100
  Pin Default 0x411111f0: [N/A] Speaker at Ext Rear
    Conn = 1/8, Color = Black
    DefAssociation = 0xf, Sequence = 0x0
    Misc = NO_PRESENCE
  Pin-ctls: 0x00: VREF_HIZ
  Unsolicited: tag=00, enabled=0
  Power states:  D0 D1 D2 D3 EPSS
  Power: setting=D0, actual=D0
Node 0x1b [Pin Complex] wcaps 0x40058f: Stereo Amp-In Amp-Out
  Amp-In caps: ofs=0x00, nsteps=0x03, stepsize=0x27, mute=0
  Amp-In vals:  [0x00 0x00]
  Amp-Out caps: ofs=0x00, nsteps=0x00, stepsize=0x00, mute=1
  Amp-Out vals:  [0x80 0x80]
  Pincap 0x00013734: IN OUT EAPD Detect
    Vref caps: HIZ 50 GRD 80 100
  EAPD 0x2: EAPD
  Pin Default 0x411111f0: [N/A] Speaker at Ext Rear
    Conn = 1/8, Color = Black
    DefAssociation = 0xf, Sequence = 0x0
    Misc = NO_PRESENCE
  Pin-ctls: 0x20: IN VREF_HIZ
  Unsolicited: tag=00, enabled=0
  Power states:  D0 D1 D2 D3 EPSS
  Power: setting=D0, actual=D0
  Connection: 2
     0x02* 0x03
Node 0x1c [Vendor Defined Widget] wcaps 0xf00000: Mono
Node 0x1d [Pin Complex] wcaps 0x400400: Mono
  Pincap 0x00000020: IN
  Pin Default 0x40679a2d: [N/A] Modem Line at Ext N/A
    Conn = Analog, Color = Pink
    DefAssociation = 0x2, Sequence = 0xd
  Pin-ctls: 0x20: IN
  Power states:  D0 D1 D2 D3 EPSS
  Power: setting=D0, actual=D0
Node 0x1e [Pin Complex] wcaps 0x400781: Stereo Digital
  Pincap 0x00000014: OUT Detect
  Pin Default 0x411111f0: [N/A] Speaker at Ext Rear
    Conn = 1/8, Color = Black
    DefAssociation = 0xf, Sequence = 0x0
    Misc = NO_PRESENCE
  Pin-ctls: 0x40: OUT
  Unsolicited: tag=00, enabled=0
  Power states:  D0 D1 D2 D3 EPSS
  Power: setting=D0, actual=D0
  Connection: 1
     0x06
Node 0x1f [Vendor Defined Widget] wcaps 0xf00000: Mono
Node 0x20 [Vendor Defined Widget] wcaps 0xf00040: Mono
  Processing caps: benign=0, ncoeff=91
Node 0x21 [Pin Complex] wcaps 0x40058d: Stereo Amp-Out
  Control: name="Headphone Playback Switch", index=0, device=0
    ControlAmp: chs=3, dir=Out, idx=0, ofs=0
  Amp-Out caps: ofs=0x00, nsteps=0x00, stepsize=0x00, mute=1
  Amp-Out vals:  [0x80 0x80]
  Pincap 0x0001001c: OUT HP EAPD Detect
  EAPD 0x2: EAPD
  Pin Default 0x03211020: [Jack] HP Out at Ext Left
    Conn = 1/8, Color = Black
    DefAssociation = 0x2, Sequence = 0x0
  Pin-ctls: 0xc0: OUT HP
  Unsolicited: tag=01, enabled=1
  Power states:  D0 D1 D2 D3 EPSS
  Power: setting=D0, actual=D0
  Connection: 2
     0x02 0x03*
Node 0x22 [Audio Mixer] wcaps 0x20010b: Stereo Amp-In
  Amp-In caps: ofs=0x00, nsteps=0x00, stepsize=0x00, mute=1
  Amp-In vals:  [0x80 0x80] [0x80 0x80] [0x80 0x80] [0x80 0x80] [0x80 0x80]
  Connection: 5
     0x18 0x19 0x1a 0x1b 0x1d
Node 0x23 [Audio Mixer] wcaps 0x20010b: Stereo Amp-In
  Amp-In caps: ofs=0x00, nsteps=0x00, stepsize=0x00, mute=1
  Amp-In vals:  [0x80 0x80] [0x80 0x80] [0x80 0x80] [0x80 0x80] [0x80 0x80] [0x00 0x00]
  Connection: 6
     0x18 0x19 0x1a 0x1b 0x1d 0x12
Node 0x24 [Audio Selector] wcaps 0x300101: Stereo
  Connection: 2
     0x12* 0x13

____________________________________________

*** /proc/asound/card2/codec#0
*** ls: -r--r--r-- 1 root root 0 2022-10-27 20:48:31.594336331 -0300 /proc/asound/card2/codec#0
Codec: Nvidia GPU 9f HDMI/DP
Address: 0
AFG Function Id: 0x1 (unsol 1)
Vendor Id: 0x10de009f
Subsystem Id: 0x104316a2
Revision Id: 0x100100
No Modem Function Group found
Default PCM:
    rates [0x0]:
    bits [0x0]:
    formats [0x0]:
Default Amp-In caps: N/A
Default Amp-Out caps: N/A
State of AFG node 0x01:
  Power states:  D0 D1 D2 D3 CLKSTOP EPSS
  Power: setting=D0, actual=D0
GPIO: io=0, o=0, i=0, unsolicited=0, wake=0
Node 0x04 [Pin Complex] wcaps 0x407381: 8-Channels Digital CP
  Pincap 0x09000094: OUT Detect HBR HDMI DP
  Pin Default 0x185600f0: [Jack] Digital Out at Int HDMI
    Conn = Digital, Color = Unknown
    DefAssociation = 0xf, Sequence = 0x0
  Pin-ctls: 0x00:
  Unsolicited: tag=01, enabled=1
  Devices: 4
     Dev 00: PD = 0, ELDV = 0, IA = 0, Connections [ 0x08* 0x09 0x0a 0x0b ]
     Dev 01: PD = 0, ELDV = 0, IA = 0, Connections [ 0x08* 0x09 0x0a 0x0b ]
     Dev 02: PD = 0, ELDV = 0, IA = 0, Connections [ 0x08* 0x09 0x0a 0x0b ]
    *Dev 03: PD = 0, ELDV = 0, IA = 0, Connections [ 0x08* 0x09 0x0a 0x0b ]
  Connection: 4
     0x08* 0x09 0x0a 0x0b
Node 0x05 [UNKNOWN Widget] wcaps 0x0: Mono
Node 0x06 [UNKNOWN Widget] wcaps 0x0: Mono
Node 0x07 [UNKNOWN Widget] wcaps 0x0: Mono
Node 0x08 [Audio Output] wcaps 0x62b1: 8-Channels Digital Stripe
  Converter: stream=0, channel=0
  Digital:
  Digital category: 0x0
  IEC Coding Type: 0x0
  PCM:
    rates [0x7f0]: 32000 44100 48000 88200 96000 176400 192000
    bits [0xe]: 16 20 24
    formats [0x5]: PCM AC3
  Unsolicited: tag=00, enabled=0
Node 0x09 [Audio Output] wcaps 0x62b1: 8-Channels Digital Stripe
  Converter: stream=0, channel=0
  Digital:
  Digital category: 0x0
  IEC Coding Type: 0x0
  PCM:
    rates [0x7f0]: 32000 44100 48000 88200 96000 176400 192000
    bits [0xe]: 16 20 24
    formats [0x5]: PCM AC3
  Unsolicited: tag=00, enabled=0
Node 0x0a [Audio Output] wcaps 0x62b1: 8-Channels Digital Stripe
  Converter: stream=0, channel=0
  Digital:
  Digital category: 0x0
  IEC Coding Type: 0x0
  PCM:
    rates [0x7f0]: 32000 44100 48000 88200 96000 176400 192000
    bits [0xe]: 16 20 24
    formats [0x5]: PCM AC3
  Unsolicited: tag=00, enabled=0
Node 0x0b [Audio Output] wcaps 0x62b1: 8-Channels Digital Stripe
  Converter: stream=0, channel=0
  Digital:
  Digital category: 0x0
  IEC Coding Type: 0x0
  PCM:
    rates [0x7f0]: 32000 44100 48000 88200 96000 176400 192000
    bits [0xe]: 16 20 24
    formats [0x5]: PCM AC3
  Unsolicited: tag=00, enabled=0

____________________________________________

*** /proc/asound/card2/eld#0.0
*** ls: -rw-r--r-- 1 root root 0 2022-10-27 20:48:31.594336331 -0300 /proc/asound/card2/eld#0.0
monitor_present		0
eld_valid		0

____________________________________________

*** /proc/asound/card2/eld#0.1
*** ls: -rw-r--r-- 1 root root 0 2022-10-27 20:48:31.594336331 -0300 /proc/asound/card2/eld#0.1
monitor_present		0
eld_valid		0

____________________________________________

*** /proc/asound/card2/eld#0.2
*** ls: -rw-r--r-- 1 root root 0 2022-10-27 20:48:31.594336331 -0300 /proc/asound/card2/eld#0.2
monitor_present		0
eld_valid		0

____________________________________________

*** /proc/asound/card2/eld#0.3
*** ls: -rw-r--r-- 1 root root 0 2022-10-27 20:48:31.594336331 -0300 /proc/asound/card2/eld#0.3
monitor_present		0
eld_valid		0

____________________________________________

*** ls: lrwxrwxrwx 1 root root 0 2022-10-27 20:24:52.033400384 -0300 /sys/class/drm/card0/device/driver -> ../../../../bus/pci/drivers/amdgpu
*** ls: lrwxrwxrwx 1 root root 0 2022-10-27 20:24:55.196733788 -0300 /sys/class/drm/card1/device/driver -> ../../../../bus/pci/drivers/nvidia
*** ls: lrwxrwxrwx 1 root root 0 2022-10-27 20:24:52.033400384 -0300 /sys/class/drm/renderD128/device/driver -> ../../../../bus/pci/drivers/amdgpu
*** ls: lrwxrwxrwx 1 root root 0 2022-10-27 20:24:55.196733788 -0300 /sys/class/drm/renderD129/device/driver -> ../../../../bus/pci/drivers/nvidia

____________________________________________

*** ls: lrwxrwxrwx 1 root root 8 2022-10-27 20:24:55.206733787 -0300 /dev/dri/by-path/pci-0000:01:00.0-card -> ../card1
*** ls: lrwxrwxrwx 1 root root 13 2022-10-27 20:24:55.206733787 -0300 /dev/dri/by-path/pci-0000:01:00.0-render -> ../renderD129
*** ls: lrwxrwxrwx 1 root root 8 2022-10-27 20:24:53.790067091 -0300 /dev/dri/by-path/pci-0000:06:00.0-card -> ../card0
*** ls: lrwxrwxrwx 1 root root 13 2022-10-27 20:24:52.043400385 -0300 /dev/dri/by-path/pci-0000:06:00.0-render -> ../renderD128
*** ls: crw-rw----+ 1 root video 226, 0 2022-10-27 20:24:53.790067091 -0300 /dev/dri/card0
*** ls: crw-rw----+ 1 root video 226, 1 2022-10-27 20:24:55.196733788 -0300 /dev/dri/card1
*** ls: crw-rw-rw- 1 root render 226, 128 2022-10-27 20:24:52.033400384 -0300 /dev/dri/renderD128
*** ls: crw-rw-rw- 1 root render 226, 129 2022-10-27 20:24:55.196733788 -0300 /dev/dri/renderD129

____________________________________________

Skipping vulkaninfo output (vulkaninfo not found)

____________________________________________

/sbin/nvidia-smi --query


==============NVSMI LOG==============

Timestamp                                 : Thu Oct 27 20:50:19 2022
Driver Version                            : 520.56.06
CUDA Version                              : 11.8

Attached GPUs                             : 1
GPU 00000000:01:00.0
    Product Name                          : NVIDIA GeForce RTX 3060 Laptop GPU
    Product Brand                         : GeForce
    Product Architecture                  : Ampere
    Display Mode                          : Disabled
    Display Active                        : Disabled
    Persistence Mode                      : Disabled
    MIG Mode
        Current                           : N/A
        Pending                           : N/A
    Accounting Mode                       : Disabled
    Accounting Mode Buffer Size           : 4000
    Driver Model
        Current                           : N/A
        Pending                           : N/A
    Serial Number                         : 0
    GPU UUID                              : GPU-fceee73c-fd00-9cc3-fead-6d6ab3715614
    Minor Number                          : 0
    VBIOS Version                         : 94.06.17.00.5F
    MultiGPU Board                        : No
    Board ID                              : 0x100
    GPU Part Number                       : N/A
    Module ID                             : 0
    Inforom Version
        Image Version                     : G001.0000.03.03
        OEM Object                        : 2.0
        ECC Object                        : N/A
        Power Management Object           : N/A
    GPU Operation Mode
        Current                           : N/A
        Pending                           : N/A
    GSP Firmware Version                  : N/A
    GPU Virtualization Mode
        Virtualization Mode               : None
        Host VGPU Mode                    : N/A
    IBMNPU
        Relaxed Ordering Mode             : N/A
    PCI
        Bus                               : 0x01
        Device                            : 0x00
        Domain                            : 0x0000
        Device Id                         : 0x252010DE
        Bus Id                            : 00000000:01:00.0
        Sub System Id                     : 0x16A21043
        GPU Link Info
            PCIe Generation
                Max                       : 3
                Current                   : 3
            Link Width
                Max                       : 16x
                Current                   : 8x
        Bridge Chip
            Type                          : N/A
            Firmware                      : N/A
        Replays Since Reset               : 0
        Replay Number Rollovers           : 0
        Tx Throughput                     : 0 KB/s
        Rx Throughput                     : 0 KB/s
    Fan Speed                             : N/A
    Performance State                     : P0
    Clocks Throttle Reasons
        Idle                              : Active
        Applications Clocks Setting       : Not Active
        SW Power Cap                      : Not Active
        HW Slowdown                       : Not Active
            HW Thermal Slowdown           : Not Active
            HW Power Brake Slowdown       : Not Active
        Sync Boost                        : Not Active
        SW Thermal Slowdown               : Not Active
        Display Clock Setting             : Not Active
    FB Memory Usage
        Total                             : 6144 MiB
        Reserved                          : 197 MiB
        Used                              : 0 MiB
        Free                              : 5946 MiB
    BAR1 Memory Usage
        Total                             : 8192 MiB
        Used                              : 1 MiB
        Free                              : 8191 MiB
    Compute Mode                          : Default
    Utilization
        Gpu                               : 0 %
        Memory                            : 0 %
        Encoder                           : 0 %
        Decoder                           : 0 %
    Encoder Stats
        Active Sessions                   : 0
        Average FPS                       : 0
        Average Latency                   : 0
    FBC Stats
        Active Sessions                   : 0
        Average FPS                       : 0
        Average Latency                   : 0
    Ecc Mode
        Current                           : N/A
        Pending                           : N/A
    ECC Errors
        Volatile
            SRAM Correctable              : N/A
            SRAM Uncorrectable            : N/A
            DRAM Correctable              : N/A
            DRAM Uncorrectable            : N/A
        Aggregate
            SRAM Correctable              : N/A
            SRAM Uncorrectable            : N/A
            DRAM Correctable              : N/A
            DRAM Uncorrectable            : N/A
    Retired Pages
        Single Bit ECC                    : N/A
        Double Bit ECC                    : N/A
        Pending Page Blacklist            : N/A
    Remapped Rows                         : N/A
    Temperature
        GPU Current Temp                  : 52 C
        GPU Shutdown Temp                 : 105 C
        GPU Slowdown Temp                 : 102 C
        GPU Max Operating Temp            : 75 C
        GPU Target Temperature            : N/A
        Memory Current Temp               : N/A
        Memory Max Operating Temp         : N/A
    Power Readings
        Power Management                  : N/A
        Power Draw                        : 24.78 W
        Power Limit                       : N/A
        Default Power Limit               : N/A
        Enforced Power Limit              : N/A
        Min Power Limit                   : N/A
        Max Power Limit                   : N/A
    Clocks
        Graphics                          : 1425 MHz
        SM                                : 1425 MHz
        Memory                            : 7000 MHz
        Video                             : 1252 MHz
    Applications Clocks
        Graphics                          : N/A
        Memory                            : N/A
    Default Applications Clocks
        Graphics                          : N/A
        Memory                            : N/A
    Max Clocks
        Graphics                          : 2100 MHz
        SM                                : 2100 MHz
        Memory                            : 7001 MHz
        Video                             : 1950 MHz
    Max Customer Boost Clocks
        Graphics                          : N/A
    Clock Policy
        Auto Boost                        : N/A
        Auto Boost Default                : N/A
    Voltage
        Graphics                          : 762.500 mV
    Processes                             : None


/sbin/nvidia-smi --query --unit


==============NVSMI LOG==============

Timestamp                                 : Thu Oct 27 20:50:19 2022
Driver Version                            : 520.56.06
CUDA Version                              : 11.8

HIC Info                                  : N/A
Attached Units                            : 0


____________________________________________

base64 "nvidia-nvml-temp6028.log"

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
gRh/IqW9FxJ4qTid1gT7W/Q=

____________________________________________

/sbin/nvidia-debugdump -D

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
ZrpD/i1cYOXUUgLnlIQB4f6vsDhOKZvTPjBzl+aARY1vOOH+77RoXZHlEQWV+U67al+SayaE/buM
M+8Nz4CNpOO4TpdLXRYzW0tbt2bTx4Q1+upPArrmt+jHdSiDWvwf7wlUc3BM9bhPuP9bCrapK32v
UzHzeI9Su5uWPuH+L3P+BXdMtoXQKUraoGjBcDatC48v8rYuP24U9vbPKcinJNz/eTatjxKxRRze
5VtQIU7i2Unhe9H/Xfypvud27y80RPXLDxGx/LG1/p32+0mukUJlwxrh+3QhFee/d5YIiOsoqX0a
eRjCQPg+XeOJB0Yq1ptNT9rYS7ge9Bvt9Ul/1lNE/FfyoOi7lI2klO8Ump6VsxNmF3UEx5I+3Ggh
PDelpOR8mUD8pIKBYtll8k/uf/v7FhiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiG
YRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiG
YRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiG
YRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiG
YRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiG
YRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiG
YRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiG
YRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiG
YRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiG
YRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiG
YRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiGYRiG
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
PyZq3RWWtnFnTP/3ENvq9jyrtn/kVB7hC8eJUyrSVbtENgzoD0d5HYrpySv6ydgcvjxlJOKieoXH
wNtrQ76z0Zj1ImtuRvZBapZ5yc6lqhB20+15miF5xqNyLuEp5AqOpFuTnZ7ShlJqIoajr35bvW7M
XcpP5KRbHvqh3h0+rMlk6LX3cklG6RRXqv2a0Gd/+8+xwwT91EO67V5p300vPQmJF4nYrKVcOv4i
texo0KUdTvu7HKR7jzmnr9xKFT39M2Ge999iu8flcyO7j3v5s4lNiuYN//3N7kcwj62JYcjk3VAk
PZBsof2o3TvcSZCkPKT0vra4WE3Qsr8LbcHF+lhViXk3YfbzzVQRO4xSeVZ+GPansbNb/CK+UGWz
Pa94H5dLS1xr1YQhWa/RI8Z3TJks+SMqyiYVrhUDL4zJjC6xnbA75q6mU0Z1jJo29gaRc//Vn+mH
dpK8MLtUVWNQStCf/e/6ntkMNLQBD+PaBEg2jdNcAyKNqJjVBeV8tSy/Pvk7WM7iKyicXrv0y2Xe
8cNY2cfsygvb//68MLsmd9aV6StZlPZHqL487/NUb/UrZwwj4+Z7RxqmGCif6FYZSGfNwq+tcKs0
Zv/n/+79vjAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAM
wzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAM
wzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAM
wzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAM
wzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAM
wzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAM
wzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAM
wzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAM
wzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAM
wzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAM
wzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAMwzAM
wzAMwzAMwzAMwzAMwzAMwzAMwzAMwzD8/9k8JYzjMzLv06LVZnubNAzmVZUm3mr9NnTaul68ezzx
4Fiq4L8dJGM3Mo5Ie/opvHX1qDtHxlPyjCeh743BlcIxK/FLD2KfN7tQxq5VtBmUVSnw/l9fDwzD
MAzDMAzDMAzD/3NHtTSp57lqB80Gn/AWCvNvzCIq5m+s8b77VdGvR2/nTAsZcRebNMud5z1ST48Z
EtHs4y9VdZ66sNmwSPaEqHIkKeP/+vPDMAzDMAzDMAzDMPy/73JFTfqulsPdbLTWvR9iH4T+F1BL
AQIAABQAAAAIAAAAAACnfpklBQEAAAABAAAOAAEAAAAAAAAAAAAAAAAAAABzeXN0ZW1faW5mby5w
YgFQSwECAAAUAAAACAAAAAAAXC3IkMUEAADABAAADQABAAAAAAAAAAAAAAAyAQAAZXJyb3JfZGF0
YS5wYgFQSwECAAAUAAAACAAAAAAAGVO0v6ReAAAw9QcACQABAAAAAAAAAAAAAAAjBgAAbnZsb2cu
bG9nAVBLAQIAABQAAAAIAAAAAAAgcO53EgAAABAAAAATAAEAAAAAAAAAAAAAAO9kAABkZWJ1Z19i
dWZmZXJzXzAwLnBiAVBLAQIAABQAAAAIAAAAAABJxjDQRWIAAMCVAAAIAAEAAAAAAAAAAAAAADNl
AABybV8wMC5wYgFQSwECAAAUAAAACAAAAAAAkXgdN8/oAAAw9QcAEAABAAAAAAAAAAAAAACfxwAA
bnZsb2cuZ3B1MDAwLmxvZwFQSwUGAAAAAAYABgBpAQAAnbABABYAQ3JlYXRlZCBieSBOdkRlYnVn
RHVtcA==

____________________________________________

/sbin/systemctl status nvidia-fabricmanager.service

____________________________________________

Skipping acpidump output (acpidump not found)

____________________________________________

End of NVIDIA bug report log file.
```
