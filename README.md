# dmap
dynamic minimal network mapper

# compile
$ clang dmap.c -o dmap

# usage
doas ./dmap -i 127.0.0.1/28 -p 22 -t connect

# options
-i  ip range (example: 192.168.1.0/28)
-p  ports (example: 21,22,53,80)
-t  scan type: ping, connect, sync

# example
![image](https://github.com/user-attachments/assets/f5c2b35c-115e-4e45-9289-96aa6f9738d7)
