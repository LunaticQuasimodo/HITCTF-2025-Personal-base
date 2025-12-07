## 一般pwn环境

启动后将chroot到`rootfs`中，并以ctf（uid 1000）的身份运行 `/pwn`，可以直接将需要的库放到`rootfs`对应目录下，无需patchelf

chroot中可用指令和`/dev`下的设备都进行了最小化，需要增加也可自行调整`rootfs`以及 `entrypoint.sh`
