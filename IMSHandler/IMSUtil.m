//
//  IMSUtil.m
//  Memory Security Demo
//
//  Created by Hannah, Robert J on 7/11/14.
//  Copyright (c) 2014 Black, Gavin S. All rights reserved.
//
//  Originals:  http://blog.timac.org/?p=886
//              http://blog.timac.org/?p=907
//

#include "IMSUtil.h"

#if TARGET_IPHONE_SIMULATOR
bool is64bitSimulator()
{
    bool is64bitSimulator = false;
    
    /* Setting up the mib (Management Information Base) which is an array of integers where each
     * integer specifies how the data will be gathered.  Here we are setting the MIB
     * block to lookup the information on all the BSD processes on the system.  Also note that
     * every regular application has a recognized BSD process accociated with it.  We pass
     * CTL_KERN, KERN_PROC, KERN_PROC_ALL to sysctl as the MIB to get back a BSD structure with
     * all BSD process information for all processes in it (including BSD process names)
     */
    int mib[6] = {0,0,0,0,0,0};
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_ALL;
    
    long numberOfRunningProcesses = 0;
    struct kinfo_proc* BSDProcessInformationStructure = NULL;
    size_t sizeOfBufferRequired = 0;
    
    /* Here we have a loop set up where we keep calling sysctl until we finally get an unrecoverable error
     * (and we return) or we finally get a succesful result.  Note with how dynamic the process list can
     * be you can expect to have a failure here and there since the process list can change between
     * getting the size of buffer required and the actually filling that buffer.
     */
    BOOL successfullyGotProcessInformation = NO;
    int error = 0;
    
    while (successfullyGotProcessInformation == NO)
    {
        /* Now that we have the MIB for looking up process information we will pass it to sysctl to get the
         * information we want on BSD processes.  However, before we do this we must know the size of the buffer to
         * allocate to accomidate the return value.  We can get the size of the data to allocate also using the
         * sysctl command.  In this case we call sysctl with the proper arguments but specify no return buffer
         * specified (null buffer).  This is a special case which causes sysctl to return the size of buffer required.
         *
         * First Argument: The MIB which is really just an array of integers.  Each integer is a constant
         *     representing what information to gather from the system.  Check out the man page to know what
         *     constants sysctl will work with.  Here of course we pass our MIB block which was passed to us.
         * Second Argument: The number of constants in the MIB (array of integers).  In this case there are three.
         * Third Argument: The output buffer where the return value from sysctl will be stored.  In this case
         *     we don't want anything return yet since we don't yet know the size of buffer needed.  Thus we will
         *     pass null for the buffer to begin with.
         * Forth Argument: The size of the output buffer required.  Since the buffer itself is null we can just
         *     get the buffer size needed back from this call.
         * Fifth Argument: The new value we want the system data to have.  Here we don't want to set any system
         *     information we only want to gather it.  Thus, we pass null as the buffer so sysctl knows that
         *     we have no desire to set the value.
         * Sixth Argument: The length of the buffer containing new information (argument five).  In this case
         *     argument five was null since we didn't want to set the system value.  Thus, the size of the buffer
         *     is zero or NULL.
         * Return Value: a return value indicating success or failure.  Actually, sysctl will either return
         *     zero on no error and -1 on error.  The errno UNIX variable will be set on error.
         */
        error = sysctl(mib, 3, NULL, &sizeOfBufferRequired, NULL, 0);
        if (error)
            return NULL;
        
        /* Now we successful obtained the size of the buffer required for the sysctl call.  This is stored in the
         * SizeOfBufferRequired variable.  We will malloc a buffer of that size to hold the sysctl result.
         */
        BSDProcessInformationStructure = (struct kinfo_proc*) malloc(sizeOfBufferRequired);
        if (BSDProcessInformationStructure == NULL)
            return NULL;
        
        /* Now we have the buffer of the correct size to hold the result we can now call sysctl
         * and get the process information.
         *
         * First Argument: The MIB for gathering information on running BSD processes.  The MIB is really
         *     just an array of integers.  Each integer is a constant representing what information to
         *     gather from the system.  Check out the man page to know what constants sysctl will work with.
         * Second Argument: The number of constants in the MIB (array of integers).  In this case there are three.
         * Third Argument: The output buffer where the return value from sysctl will be stored.  This is the buffer
         *     which we allocated specifically for this purpose.
         * Forth Argument: The size of the output buffer (argument three).  In this case its the size of the
         *     buffer we already allocated.
         * Fifth Argument: The buffer containing the value to set the system value to.  In this case we don't
         *     want to set any system information we only want to gather it.  Thus, we pass null as the buffer
         *     so sysctl knows that we have no desire to set the value.
         * Sixth Argument: The length of the buffer containing new information (argument five).  In this case
         *     argument five was null since we didn't want to set the system value.  Thus, the size of the buffer
         *     is zero or NULL.
         * Return Value: a return value indicating success or failure.  Actually, sysctl will either return
         *     zero on no error and -1 on error.  The errno UNIX variable will be set on error.
         */
        error = sysctl(mib, 3, BSDProcessInformationStructure, &sizeOfBufferRequired, NULL, 0);
        if (error == 0)
        {
            //Here we successfully got the process information.  Thus set the variable to end this sysctl calling loop
            successfullyGotProcessInformation = YES;
        }
        else
        {
            /* failed getting process information we will try again next time around the loop.  Note this is caused
             * by the fact the process list changed between getting the size of the buffer and actually filling
             * the buffer (something which will happen from time to time since the process list is dynamic).
             * Anyways, the attempted sysctl call failed.  We will now begin again by freeing up the allocated
             * buffer and starting again at the beginning of the loop.
             */
            free(BSDProcessInformationStructure);
        }
    } //end while loop
    
    
    /* Now that we have the BSD structure describing the running processes we will parse it for the desired
     * process name.  First we will the number of running processes.  We can determine
     * the number of processes running because there is a kinfo_proc structure for each process.
     */
    numberOfRunningProcesses = sizeOfBufferRequired / sizeof(struct kinfo_proc);
    for (int i = 0; i < numberOfRunningProcesses; i++)
    {
        //Getting name of process we are examining
        const char *name = BSDProcessInformationStructure[i].kp_proc.p_comm;
        
        if(strcmp(name, "SimulatorBridge") == 0)
        {
            int p_flag = BSDProcessInformationStructure[i].kp_proc.p_flag;
            is64bitSimulator = (p_flag & P_LP64) == P_LP64;
            break;
        }
    }
    
    free(BSDProcessInformationStructure);
    return is64bitSimulator;
}

#endif // TARGET_IPHONE_SIMULATOR

BOOL is64bitHardware(){
#if __LP64__
    // The app has been compiled for 64-bit intel and runs as 64-bit intel
    return YES;
#endif
    
    // Use some static variables to avoid performing the tasks several times.
    static BOOL sHardwareChecked = NO;
    static BOOL sIs64bitHardware = NO;
    
    if(!sHardwareChecked)
    {
        sHardwareChecked = YES;
        
#if TARGET_IPHONE_SIMULATOR
        // The app was compiled as 32-bit for the iOS Simulator.
        // We check if the Simulator is a 32-bit or 64-bit simulator using the function is64bitSimulator()
        // See http://blog.timac.org/?p=886
        sIs64bitHardware = is64bitSimulator();
#else
        // The app runs on a real iOS device: ask the kernel for the host info.
        struct host_basic_info host_basic_info;
        unsigned int count;
        kern_return_t returnValue = host_info(mach_host_self(), HOST_BASIC_INFO, (host_info_t)(&host_basic_info), &count);
        if(returnValue != KERN_SUCCESS)
        {
            sIs64bitHardware = NO;
        }
        
        sIs64bitHardware = (host_basic_info.cpu_type == CPU_TYPE_ARM64);
        
#endif // TARGET_IPHONE_SIMULATOR
    }
    
    return sIs64bitHardware;
}

