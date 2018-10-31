//////////////////////////////////////////////////////////////////////
//                      North Carolina State University
//
//
//
//                             Copyright 2016
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
//     Core of Kernel Module for Memory Container
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

extern struct miscdevice memory_container_dev;
struct container_list containerHead;

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
   struct mutex *contLock;
};


int memory_container_init(void)
{
    int ret;

    if ((ret = misc_register(&memory_container_dev)))
    {
        printk(KERN_ERR "Unable to register \"memory_container\" misc device\n");
        return ret;
    }

    printk(KERN_ERR "\"memory_container\" misc device installed\n");
    printk(KERN_ERR "\"memory_container\" version 0.1\n");
    INIT_LIST_HEAD(&containerHead.list);
    return ret;
}


void memory_container_exit(void)
{
    struct list_head *p,*q,*pp1,*pq1,*pp2,*pq2;
    struct task_list *tempProcObj;
    struct memObj *memOb;
    struct memObj *tempTu;
    struct container_list *tempCnt,*tempCont;

    list_for_each_safe(p,q,&containerHead.list)
    {
            tempCont = list_entry(p, struct container_list,list);
            list_for_each_safe(pp2, pq2, &((tempCont->head).list))
            {
                tempProcObj = list_entry(pp2,struct task_list,list);
                if(tempProcObj!=NULL && tempProcObj->processId == current->pid)
                {
		    tempCnt = tempCont;
                }
            }
     }
    tempProcObj = &(tempCnt->head);
    memOb = &(tempCnt->mHead);
    if(list_empty_careful(&tempProcObj->list) && !list_empty_careful(&memOb->list))
    {
     list_for_each_safe(pp1,pq1,&((tempCnt->mHead).list))
        {
            tempTu = list_entry(pp1,struct memObj,list);
            if(tempTu!=NULL)
            {
                list_del(&tempTu->list);
		kfree(tempTu);
            }
        }
    }
    misc_deregister(&memory_container_dev);
}
