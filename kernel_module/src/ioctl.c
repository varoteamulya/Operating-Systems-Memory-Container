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
struct container_list *isConatinerPresent(__u64 id);
void CreateContainerWithCid(__u64 kcid,pid_t proId);
struct task_list *isProcessPresent(struct container_list *container, pid_t procId);
int associateProcToContainer(struct container_list *container, pid_t procId);
struct container_list *searchContainerByProcId(pid_t procsId);

extern struct container_list containerHead;
static DEFINE_MUTEX(lock);
void *address=NULL;

struct task_list
{
  pid_t processId;
  struct list_head list;
};

struct memObj
{
  __u64 oid;
  __u64 addr;
  size_t oSize;
  struct list_head list;
  void *data;
};

struct container_list
{
   __u64 cid;
   struct task_list head;
   struct memObj mHead;
   struct list_head list;
   struct mutex contLock;
};

int memory_container_mmap(struct file *filp, struct vm_area_struct *vma)
{
//    printk("Entered memory_container_mmap\n");
    size_t size = vma->vm_end - vma->vm_start;
    int ret =0;
    struct memObj *tempMemObj;
    struct list_head *p2,*q2;
    struct container_list *tempCont;

    mutex_lock(&lock);
    tempCont = searchContainerByProcId(current->pid);
    mutex_unlock(&lock);
    list_for_each_safe(p2, q2, &((tempCont->mHead).list))
    {
        tempMemObj = list_entry(p2,struct memObj,list);
        if(tempMemObj!=NULL && tempMemObj->oid==vma->vm_pgoff)
        {
            ret = remap_pfn_range(vma, vma->vm_start, tempMemObj->addr,size,vma->vm_page_prot);
            if(ret<0)
	    {
	        printk("Memory mapping failed\n");
                return -EIO;
            }
	    return ret;
        }
    }

    address = kcalloc(1,(size), GFP_KERNEL);
    if (address == NULL)
    {
	printk("kmalloc allocation is null\n");
        return -1;
    }
    else
    {
    	tempMemObj = (struct memObj *)kmalloc(sizeof(struct memObj),GFP_KERNEL);
        tempMemObj->oid = vma->vm_pgoff;
        unsigned long pfn = virt_to_phys((void *)(long unsigned int)address)>>PAGE_SHIFT;
        tempMemObj->addr = pfn;
	tempMemObj->oSize = size;
        tempMemObj->data = address;
        ret = remap_pfn_range(vma, vma->vm_start, pfn,vma->vm_end - vma->vm_start,vma->vm_page_prot);
        if(ret<0)
	{
 	    printk("Error in address mapping\n");
	    return -EIO;
	}
        mutex_lock(&lock);
        list_add(&(tempMemObj->list),&((tempCont->mHead).list));
        mutex_unlock(&lock);
    }
    return ret;
}


int memory_container_lock(struct memory_container_cmd __user *user_cmd)
{
//    printk("Accessing the container lock");
    struct container_list *tempC = NULL;
    struct memory_container_cmd kcmd;
    copy_from_user(&kcmd, (void __user*)user_cmd, sizeof(struct memory_container_cmd));
    mutex_lock(&lock);
    tempC = searchContainerByProcId(current->pid);
    mutex_unlock(&lock);
    if(tempC == NULL)
    {
        printk("No container is associated with this process\n");
        return 0;
    }
    mutex_lock(&tempC->contLock);
    return 0;
}


int memory_container_unlock(struct memory_container_cmd __user *user_cmd)
{
  //  printk("Accessing the container unLock");
    struct container_list *tempCu = NULL;
    struct memory_container_cmd kcmd;
    copy_from_user(&kcmd, (void __user*)user_cmd, sizeof(struct memory_container_cmd));
    mutex_lock(&lock);
    tempCu = searchContainerByProcId(current->pid);
    mutex_unlock(&lock);
    if(tempCu == NULL)
    {
        printk("No container is associated with this process\n");
        return 0;
    }
    mutex_unlock(&tempCu->contLock);
    return 0;
}


int memory_container_delete(struct memory_container_cmd __user *user_cmd)
{
    //printk("Delete the process from the container list\n");
    struct container_list *deleteProcInCont = NULL;
    struct task_list *deAssociateProc = NULL;
    struct task_list *tempTask;
    struct memObj *tMemObj;
    struct list_head *dp,*dq;
    mutex_lock(&lock);
    deleteProcInCont = searchContainerByProcId(current->pid);
    mutex_unlock(&lock);
    if(deleteProcInCont == NULL)
    {
	printk("Container with proc id: %u not present\n", current->pid);
	return 0;
    }
    else
    {
	list_for_each_safe(dp,dq,&((deleteProcInCont->head).list))
	{
	    deAssociateProc = list_entry(dp,struct task_list,list);
	    if(deAssociateProc!=NULL && deAssociateProc->processId == current->pid)
            {
  		mutex_lock(&lock);
		list_del(&deAssociateProc->list);
		mutex_unlock(&lock);
		kfree(deAssociateProc);
  	    }
	}
    }
    tempTask =&(deleteProcInCont->head);
    tMemObj = &(deleteProcInCont->mHead);
    if(list_empty_careful(&tempTask->list) && list_empty_careful(&tMemObj->list))
    {
	printk("Container should be removed\n");
	mutex_lock(&lock);
        list_del(&deleteProcInCont->list);
	mutex_unlock(&lock);
	kfree(deleteProcInCont);
    }
    return 0;
}

struct container_list *searchContainerByProcId(pid_t procsId)
{
//    printk("Search Container by Process id:%d \n", procsId);
    struct list_head *sp,*sq, *sp1,*sq1;
    struct task_list *tempProc;
    struct container_list *tCont;
    list_for_each_safe(sp,sq,&containerHead.list)
    {
        tCont = list_entry(sp, struct container_list,list);
        list_for_each_safe(sp1, sq1, &((tCont->head).list))
        {
            tempProc = list_entry(sp1,struct task_list,list);
	    if(tempProc!=NULL && tempProc->processId == procsId)
	    {
                return tCont;
	    }
        }
    }
    return NULL;
}

struct container_list *isConatinerPresent(__u64 id)
{
//   printk("Check iscontainerpresent\n ");
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
  //   printk("creating the container ");
     struct container_list *tmp;
     //Creating a new container
     tmp = (struct container_list *)kmalloc(sizeof(struct container_list), GFP_KERNEL);
     tmp->cid = kcid;
     INIT_LIST_HEAD(&tmp->head.list);
     INIT_LIST_HEAD(&tmp->mHead.list);
     mutex_init(&tmp->contLock);
     mutex_lock(&lock);
     list_add(&(tmp->list),&(containerHead.list));
     struct task_list *intermediateProc;
     intermediateProc = isProcessPresent(tmp, proId);
     mutex_unlock(&lock);
     if(intermediateProc == NULL)
     {
         associateProcToContainer(tmp,proId);
     }
}

struct task_list *isProcessPresent(struct container_list *container, pid_t procId)
{
  // printk("Checking is ProcessPresent\n");
   struct task_list *tThreadTemp;
   struct list_head *p,*q;
   list_for_each_safe(p, q,&((container->head).list))
   {
      tThreadTemp = list_entry(p, struct task_list, list);
      if(tThreadTemp!=NULL && tThreadTemp->processId == procId)
      {
        printk("task pid matched: %u\n", procId);
        return tThreadTemp;
      }
   }
   return NULL;
}

int associateProcToContainer(struct container_list *container, pid_t procId)
{
    // printk("associate process to conatiner %llu with pid as %u ", container->cid, procId);
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
//    printk("Entered create container\n");
    struct memory_container_cmd kcmd;
    struct container_list *intermediateContainer;
    copy_from_user(&kcmd, (void __user*)user_cmd, sizeof(struct memory_container_cmd));
    mutex_lock(&lock);
    intermediateContainer = isConatinerPresent(kcmd.cid);
    mutex_unlock(&lock);
    pid_t processIdOfTask = current->pid;
    if(intermediateContainer==NULL)
    {
    //    printk("Container doesn't exist, creating one now with cid: %llu \n",kcmd.cid);
    	CreateContainerWithCid(kcmd.cid,processIdOfTask);
    }
   else
   {
      // printk("Creating and allocating the processor with id: %u to list\n",processIdOfTask);
       associateProcToContainer(intermediateContainer,processIdOfTask);
   }
    return 0;
}


int memory_container_free(struct memory_container_cmd __user *user_cmd)
{
  //  printk("Memory Container Free\n");
    struct memory_container_cmd kcmd;
    copy_from_user(&kcmd, (void __user*)user_cmd, sizeof(struct memory_container_cmd));
    struct container_list *tempCont = NULL;
    struct memObj *freeMemObj = NULL;
    struct list_head *fp,*fq;
    mutex_lock(&lock);
    tempCont = searchContainerByProcId(current->pid);
    mutex_unlock(&lock);
    if(tempCont == NULL)
    {
        printk("No container found for this process id:%u \n", current->pid);
	return 0;
    }
    list_for_each_safe(fp,fq,&((tempCont->mHead).list))
    {
        freeMemObj = list_entry(fp,struct memObj,list);
        if(freeMemObj!=NULL && freeMemObj->oid == kcmd.oid)
        {
 	//    printk("Freeing memory here\n");
	    mutex_lock(&lock);
            list_del(&freeMemObj->list);
	    mutex_unlock(&lock);
	    kfree(freeMemObj);
  	}
    }
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
