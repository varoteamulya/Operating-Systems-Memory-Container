//////////////////////////////////////////////////////////////////////
//                      North Carolina State University
//
//
//
//                             Copyright 2018
//
////////////////////////////////////////////////////////////////////////
//
// This program is free software; you can redistribute it and/or modify it
// under the terms and conditions of the GNU General Public License,
// version 2, as published by the Free Software Foundation.
//
// This program is distributed in the hope it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
//
////////////////////////////////////////////////////////////////////////
//
//   Author:  Hung-Wei Tseng, Yu-Chia Liu
//
//   Description:
//     Core of Kernel Module for Processor Container
//
////////////////////////////////////////////////////////////////////////

#include "memory_container.h"

#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/poll.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/kthread.h>

phys_addr_t virt_to_phys(volatile void * address);
int remap_pfn_range(struct vm_area_struct *vma,unsigned long addr,unsigned long pfn,unsigned long size,pgprot_t prot);
void *address=NULL;
struct container_list *isConatinerPresent(__u64 id);
void CreateContainerWithCid(__u64 kcid);
struct task_list *isProcessPresent(struct container_list *container, pid_t procId);
int associateProcToContainer(struct container_list *container);

extern struct container_list containerHead;
static DEFINE_MUTEX(lock);

struct task_list
{
  pid_t processId;
  struct list_head list;
};

struct memObj
{
  __u64 oid;
  __u64 addr;
  __u64 oSize;
  struct list_head list;
}

struct container_list
{
   __u64 cid;
   struct task_list head;
   struct memObj head;
   struct list_head list;
   struct list_head objList;
};

int memory_container_mmap(struct file *filp, struct vm_area_struct *vma)
{
    printk("Entered memory_container_mmap\n");
    __u64 size = vma->vm_end - vma->vm_start;
    int ret = 0;

    if (address == NULL)
    {
    	address = kcalloc(1, size, GFP_KERNEL);
    	printk("address=%d\t", address);
    	printk("size=%lu\t", size);
    	printk("pid:%d\t pid_name:%s\n", current->pid, current->comm);
    }

    unsigned long pfn = virt_to_phys((void *)address)>>PAGE_SHIFT;
    ret = remap_pfn_range(vma, vma->vm_start, pfn,
    			    vma->vm_end - vma->vm_start,
    			    vma->vm_page_prot);
    if (ret < 0)
   {
	printk("remap failed\n");
        return -EAGAIN;
    }
     return 0;
}


int memory_container_lock(struct memory_container_cmd __user *user_cmd)
{
    return 0;
}


int memory_container_unlock(struct memory_container_cmd __user *user_cmd)
{
    return 0;
}


int memory_container_delete(struct memory_container_cmd __user *user_cmd)
{
    return 0;
}

struct container_list *isConatinerPresent(__u64 id)
{
   printk("Check iscontainerpresent\n ");
   struct container_list *temp;
   struct list_head *pos,*p;

   //Traversing the list
   list_for_each_safe(pos,p,&containerHead.list)
    {
      temp = list_entry(pos, struct container_list, list);
      if(temp!=NULL && temp->cid == id)
        {
         return temp;
        }
    }

    return NULL;
}


void CreateContainerWithCid(__u64 kcid,pid_t proId)
{
     printk("creating the container ");
     struct container_list *tmp;
     //Creating a new container
     tmp = (struct container_list *)kmalloc(sizeof(struct container_list), GFP_KERNEL);
     tmp->cid = kcid;
     INIT_LIST_HEAD(&tmp->head.list);
     //Adding the container to the list
     mutex_lock(&lock);
     list_add(&(tmp->list),&(containerHead.list));
     mutex_unlock(&lock);
     struct task_list *intermediateProc;
     intermediateProc = isProcessPresent(tmp, proId);
     if(intermediateThread == NULL)
     {
         associateProcToContainer(tmp);
     }
}

struct task_list *isProcessPresent(struct container_list *container, pid_t procId)
{
    printk("Checking is ProcessPresent\n");

   struct task_list *tThreadTemp;
   struct list_head *p,*q;
   list_for_each_safe(p, q,&((container->head).list))
   {
      tThreadTemp = list_entry(p, struct task_list, list);
      if(tThreadTemp!=NULL && tThreadTemp->processId == procId)
      {
        printk("task pid matched: %uld\n", procId);
        return tThreadTemp;
      }
   }
   return NULL;
}

int associateProcToContainer(struct container_list *container, pid_t procId)
{
     printk("associate process to conatiner %llu with pid as %ld ", container->cid, procId);
     struct task_list *tTmp;
     tTmp = (struct task_list *)kmalloc(sizeof(struct task_list), GFP_KERNEL);
     mutex_lock(&lock);
     tTmp->processId = procId;
     list_add(&(tTmp->list), &((container->head).list));
     mutex_unlock(&lock);

     return 0;
}

int memory_container_create(struct memory_container_cmd __user *user_cmd)
{
    printk("Entered create container\n");
    struct memory_container_cmd kcmd;
    struct container_list *intermediateContainer;
    copy_from_user(&kcmd, (void __user*)user_cmd, sizeof(struct memory_container_cmd));
    intermediateContainer = isContainerPresent(kcmd.cid);
    pid_t processIdOfTask = current->pid;
    if(intermediateContainer==NULL)
    {
        printk("Container doesn't exist, creating one now with cid: %llu \n",kcmd.cid);
    	CreateContainerWithCid(kcmd.cid,processIdOfTask);
    }
   else
   {
       printk("Creating and allocating the processor with id: %ld to list\n",processIdOfTask);
       associateProcToContainer(kcmd.cid,processIdOfTask);
   }


    return 0;
}


int memory_container_free(struct memory_container_cmd __user *user_cmd)
{
    return 0;
}


/**
 * control function that receive the command in user space and pass arguments to
 * corresponding functions.
 */
int memory_container_ioctl(struct file *filp, unsigned int cmd,
                              unsigned long arg)
{
    switch (cmd)
    {
    case MCONTAINER_IOCTL_CREATE:
        return memory_container_create((void __user *)arg);
    case MCONTAINER_IOCTL_DELETE:
        return memory_container_delete((void __user *)arg);
    case MCONTAINER_IOCTL_LOCK:
        return memory_container_lock((void __user *)arg);
    case MCONTAINER_IOCTL_UNLOCK:
        return memory_container_unlock((void __user *)arg);
    case MCONTAINER_IOCTL_FREE:
        return memory_container_free((void __user *)arg);
    default:
        return -ENOTTY;
    }
}
