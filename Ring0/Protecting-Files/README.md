

# Trev Kit

## 📌 Overview


This kernel module demonstrates how to use ftrace hooking to intercept and modify the behavior of Linux system calls.
It hooks the following syscalls:

- read → Alters the contents of a specific file (/tmp/data.txt)
- mount → Blocks mounting of certain paths
- kill → Provides hidden commands for toggling module visibility and privilege escalation

### The Kill Hook 

- The kit will hook the kill sys call to escalate privileges and to make the kit visible (e.g: in `lsmod`)
```bash
kill -44 0 # hides or shows the kit
kill -45 0 # sets root
```

 ### The Read Hook 

 - The read hook will protect the content of the file under the constant `TARGET_FILE` therefore, preventing modifications to this file even by root user
 - The static content of the file is under `DATA` constant hence, only that specific data will be inside that file
```bash
cat /root/data.txt
Hello World
```
- File size is forced to `DATA_LEN` bytes
- Reads beyond this length return 0 (EOF) 

### The Mount Hook 

2. Blocking Mounts (Hooking mount)

Prevents mounting sensitive paths:

```bash
/root/data.txt
/root
/
```
If either source or target is one of these, the call is denied. 
