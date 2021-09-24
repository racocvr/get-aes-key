/**
* @file    [Mandatory] tee_client_api.h
* @brief   [Mandatory] This header defines APIs of TEE Client API specification in
                       GlobalPlatform Standard.
* @version [Mandatory] Mark Version: 2.4 / 3.0
* @details [Optional] This header defines a communication API for connecting
                      Client Applications running in a rich operation environment
                      with security related Trusted Applications running inside a
                      Trusted Execution environment.
*
* Copyright 2013 by Samsung Electronics, Inc.,
*
* This software is the confidential and proprietary information
* of Samsung Electronics, Inc. ("Confidential Information"). You
* shall not disclose such Confidential Information and shall use
* it only in accordance with the terms of the license agreement
* you entered into with Samsung.
*/


#ifndef __TEE_CLIENT_API_H__
#define __TEE_CLIENT_API_H__

#include <stdint.h>
#include <stddef.h>
#include <sys/queue.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return Code Constants */
#define TEEC_SUCCESS				0x00000000 /**< The operation was successful */
#define TEEC_ERROR_GENERIC			0xFFFF0000 /**< Non-specific cause */
#define TEEC_ERROR_ACCESS_DENIED	0xFFFF0001 /**< Access privileges are not sufficient */
#define TEEC_ERROR_CANCEL			0xFFFF0002 /**< The operation was cancelled */
#define TEEC_ERROR_ACCESS_CONFLICT	0xFFFF0003 /**< Concurrent accesses caused conflict */
#define TEEC_ERROR_EXCESS_DATA		0xFFFF0004 /**< Too much data for the requested operation was passed */
#define TEEC_ERROR_BAD_FORMAT		0xFFFF0005 /**< Input data was of invalid format */
#define TEEC_ERROR_BAD_PARAMETERS	0xFFFF0006 /**< Input parameters were invalid */
#define TEEC_ERROR_BAD_STATE		0xFFFF0007 /**< Operation is not valid in the current state */
#define TEEC_ERROR_ITEM_NOT_FOUND	0xFFFF0008 /**< The requested data item is not found */
#define TEEC_ERROR_NOT_IMPLEMENTED	0xFFFF0009 /**< The requested operation should exist but is not yet implemented */
#define TEEC_ERROR_NOT_SUPPORTED	0xFFFF000A /**< The requested operation is valid but is not supported in this Implementation */
#define TEEC_ERROR_NO_DATA			0xFFFF000B /**< Expected data was missing */
#define TEEC_ERROR_OUT_OF_MEMORY	0xFFFF000C /**< System ran out of resources */
#define TEEC_ERROR_BUSY				0xFFFF000D /**< The system is busy working on something else. */
#define TEEC_ERROR_COMMUNICATION	0xFFFF000E /**< Communication with a remote party failed. */
#define TEEC_ERROR_SECURITY			0xFFFF000F /**< A security fault was detected. */
#define TEEC_ERROR_SHORT_BUFFER		0xFFFF0010 /**< The supplied buffer is too short for the generated output. */
#define TEEC_ERROR_TARGET_DEAD		0xFFFF3024 /**< Targed TA panic'ed */

#define TEEC_ERROR_SECURITY_EXT_IMAGE 	  0x80010001
#define TEEC_ERROR_SECURITY_EXT_MANIFEST  0x80010002
#define TEEC_ERROR_SECURITY_EXT_SET_CERT  0x80010003
#define TEEC_ERROR_SECURITY_EXT_VERIFY_CERT 0x80010004
#define TEEC_ERROR_SECURITY_EXT_VERIFY_PACKAGE 0x80010005
#define TEEC_ERROR_SECURITY_EXT_DECRYPT   0x80010006
#define TEEC_ERROR_SECURITY_EXT_VERSION   0x80010007
#define TEEC_ERROR_SECURITY_EXT_BOOT_MODE 0x80010008

#define TEEC_IMP_MIN				0x00000001 /**< Minimum Implementation-Defined API return code constants */
#define TEEC_IMP_MAX				0xFFFEFFFF /**< Maximum Implementation-Defined API return code constants */
#define TEEC_RFU_MIN				0xFFFF0011 /**< Minimum Reserved for Future Use API return code constants */
#define TEEC_RFU_MAX				0xFFFFFFFF /**< Maximum Reserved for Future Use API return code constants */

/* Return Code Origins */
#define TEEC_ORIGIN_API				0x1 /**< The return code is an error that originated within the TEE Client API implementation. */
#define TEEC_ORIGIN_COMMS			0x2 /**< The return code is an error that originated within the underlying communications stack
											 linking the rich OS with the TEE. */
#define TEEC_ORIGIN_TEE				0x3 /**< The return code is an error that originated within the common TEE code. */
#define TEEC_ORIGIN_TRUSTED_APP		0x4 /**< The return code originated within the Trusted Application code. This includes
											 the case where the return code is a success. */
typedef uint32_t TEEC_Result;

/**
* @brief   [Mandatory] This type contains a Universally Unique Resource Identifier (UUID) type as defined in RFC4122.
					   These UUID values are used to identify Trusted Applications.
* @details [Optional]
* @see     [Optional]
*/
typedef struct
{
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t clockSeqAndNode[8];
} TEEC_UUID;

/**
* @brief   [Mandatory] This type denotes a TEE Context, the main logical container linking a Client Application with
					   a particular TEE. Its contents is entirely implementation-defined.
* @details [Optional]
* @see     [Optional]
*/
typedef struct
{
	void* imp;
} TEEC_Context;

/**
* @brief   [Mandatory] This type denotes a TEE Session, the logical container linking a Client Application with
					   a particular Trusted Application. Its contents is entirely implementation-defined.
* @details [Optional]
* @see     [Optional]
*/
typedef struct
{
	void *imp;
} TEEC_Session;

/* Configuration Constants */
#define TEEC_CONFIG_SHAREDMEM_MAX_SIZE 0x1000000 /**< The maximum size of a single Shared Memory block, in bytes, of both API
														allocated and API registered memory. */
/* Shared Memory Control Flags */
#define TEEC_MEM_INPUT			(1 << 0) /**< The Shared Memory can carry data from the Client Application to the
												Trusted Application. */
#define TEEC_MEM_OUTPUT			(1 << 1) /**< The Shared Memory can carry data from the Trusted Application to the
												Client Application. */

#define TEEC_NONE					0x00000000 /**< The Parameter is not used */
#define TEEC_VALUE_INPUT			0x00000001 /**< The Parameter is a TEEC_Value tagged as input. */
#define TEEC_VALUE_OUTPUT			0x00000002 /**< The Parameter is a TEEC_Value tagged as output */
#define TEEC_VALUE_INOUT			0x00000003 /**< The Parameter is a TEEC_Value tagged as both as input and output,
													i.e., for which both the behaviors of TEEC_VALUE_INPUT and
													TEEC_VALUE_OUTPUT apply. */
#define TEEC_MEMREF_TEMP_INPUT		0x00000005 /**< The Parameter is a TEEC_TempMemoryReference describing a region of
													memory which needs to be temporarily registered for the duration of
													the Operation and is tagged as input. */
#define TEEC_MEMREF_TEMP_OUTPUT		0x00000006 /**< Same as TEEC_MEMREF_TEMP_INPUT, but the Memory Reference is tagged
													as output. The Implementation may update the size field to reflect
													the required output size in some use cases. */
#define TEEC_MEMREF_TEMP_INOUT		0x00000007 /**< A Temporary Memory Reference tagged as both input and output,
													i.e., for which both the behaviors of TEEC_MEMREF_TEMP_INPUT and
													TEEC_MEMREF_TEMP_OUTPUT apply. */
#define TEEC_MEMREF_WHOLE			0x0000000C /**< The Parameter is a Registered Memory Reference that refers
													to the entirety of its parent Shared Memory block. The parameter
													structure is a TEEC_MemoryReference. In this structure, the Implementation
													MUST read only the parent field and MAY update the size field when
													the operation completes. */
#define TEEC_MEMREF_PARTIAL_INPUT	0x0000000D /**< A Registered Memory Reference structure that refers to a partial region
													of its parent Shared Memory block and is tagged as input. */
#define TEEC_MEMREF_PARTIAL_OUTPUT	0x0000000E /**< A Registered Memory Reference structure that refers to a partial region
													of its parent Shared Memory block and is tagged as output. */
#define TEEC_MEMREF_PARTIAL_INOUT	0x0000000F /**< The Registered Memory Reference structure that refers to a partial region
													of its parent Shared Memory block and is tagged as both input and output,
													i.e., for which both the behaviors of TEEC_MEMREF_PARTIAL_INPUT and
													TEEC_MEMREF_PARTIAL_OUTPUT apply. */



/* These definitions are implementation internal use only. These definitions will be moved to internal header */
#define TEE_PARAM_TYPE_NONE				0x00000000
#define TEE_PARAM_TYPE_VALUE_INPUT		0x00000001
#define TEE_PARAM_TYPE_VALUE_OUTPUT		0x00000002
#define TEE_PARAM_TYPE_VALUE_INOUT		0x00000003
#define TEE_PARAM_TYPE_MEMREF_INPUT		0x00000005
#define TEE_PARAM_TYPE_MEMREF_OUTPUT	0x00000006
#define TEE_PARAM_TYPE_MEMREF_INOUT		0x00000007

#define TEEC_SHMEM_IMP_NONE				0x00000000
#define TEEC_SHMEM_IMP_ALLOCED			0x00000001


/**
* @brief   [Mandatory] This type denotes a TEE Context, the main logical container linking a Client Application with
					   a particular TEE. Its contents is entirely implementation-defined.
* @details [Optional]
* @see     [Optional]
*/
typedef struct sTEEC_SharedMemoryImp
{
	LIST_ENTRY(sTEEC_SharedMemoryImp) list;
	TEEC_Context *context;
	void *context_imp;
	uint32_t flags;
	int	memid;
} TEEC_SharedMemoryImp;

/**
* @brief   [Mandatory] This type denotes a Shared Memory block which has either been registered with the implementation
					   or allocated by it.
* @details [Optional]
* @see     [Optional]
*/
typedef struct
{
	void *buffer;
	uint32_t size;
	uint32_t flags;
	TEEC_SharedMemoryImp imp;	/* See above */
} TEEC_SharedMemory;


/**
* @brief   [Mandatory] This type defines a Temporary Memory Reference. It is used as a TEEC_Operation parameter when
					   the corresponding parameter type is one of TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
					   or TEEC_MEMREF_TEMP_INOUT.
* @details [Optional]
* @see     [Optional]
*/
typedef struct
{
	void *buffer;
	uint32_t size;
} TEEC_TempMemoryReference;

/**
* @brief   [Mandatory] This type defines a Registered Memory Reference, i.e., that uses a pre-registered or pre-allocated
						   Shared Memory block. It is used as a TEEC_Operation parameter when the corresponding parameter type
						   is one of TEEC_MEMREF_WHOLE, TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT, or TEEC_MEMREF_PARTIAL_INOUT.
* @details [Optional]
* @see     [Optional]
*/
typedef struct
{
	TEEC_SharedMemory* parent;
	uint32_t size;
	uint32_t offset;
} TEEC_RegisteredMemoryReference;

/**
* @brief   [Mandatory] This type defines a parameter that is not referencing shared memory, but carries instead small
					   raw data passed by value. It is used as a TEEC_Operation parameter when the corresponding parameter type
					   is one of TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT, or TEEC_VALUE_INOUT.
* @details [Optional]
* @see     [Optional]
*/
typedef struct
{
	uint32_t a;
	uint32_t b;
} TEEC_Value;

/**
* @brief   [Mandatory] This type defines a Parameter of a TEEC_Operation. It can be a Temporary Memory Reference, a Registered
					   Memory Reference, or a Value Parameter.
* @details [Optional]
* @see     [Optional]
*/
typedef union
{
	TEEC_TempMemoryReference tmpref;
	TEEC_RegisteredMemoryReference memref;
	TEEC_Value value;
} TEEC_Parameter;

/* Session Login Methods */
#define TEEC_LOGIN_PUBLIC				0x00000000 /**< No login data is provided. */
#define TEEC_LOGIN_USER					0x00000001 /**< Login data about the user running the Client Application process
														is provided. */
#define TEEC_LOGIN_GROUP				0x00000002 /**< Login data about the group running the Client Application process
														is provided. */
#define TEEC_LOGIN_APPLICATION			0x00000004 /**< Login data about the running Client Application itself is provided. */
#define TEEC_LOGIN_USER_APPLICATION		0x00000005 /**< Login data about the user running the Client Application and about
														the Client Application itself is provided. */
#define TEEC_LOGIN_GROUP_APPLICATION	0x00000006 /**< Login data about the group running the Client Application and about
														the Client Application itself is provided. */
#define TEEC_LOGIN_IMP_MIN				0x80000000  /**< Minumum Reserved for implementation-defined connection methods */
#define TEEC_LOGIN_IMP_MAX				0xFFFFFFFF  /**< Maximum Reserved for implementation-defined connection methods */


/**
* @brief   [Mandatory] This type defines the payload of either an open Session operation or an invoke Command operation.
					   It is also used for cancellation of operations, which may be desirable even if no payload is passed.
* @details [Optional]
* @see     [Optional]
*/
typedef struct
{
	uint32_t started;
	uint32_t paramTypes;
	TEEC_Parameter params[4];
	void *imp;
} TEEC_Operation;

typedef struct TEEC_SoftwareInfo_Struct {
	char secos_build_id[42];
	char secos_machine_name[32];
	char linux_module_build_id[42];
	char lib_build_id[42];
	char secos_build_type[32];
	char linux_module_build_type[32];
	char lib_build_type[32];
} TEEC_SoftwareInfo;


/* TEE Client API functions and macros definitions */

/**
* @brief     [Mandatory] This function initializes a new TEE Context, forming a connection between this Client Application
						 and the TEE identified by the string identifier name.
* @param     [Mandatory] [in] name : a zero-terminated string that describes the TEE to connect to. If this parameter is set to
							  NULL the Implementation MUST select a default TEE. Currently, default TEE is "ARM TrustZone"
* @param     [Mandatory] [out] context : a TEEC_Context structure that MUST be initialized by the Implementation.
* @pre       [Mandatory] N/A
* @post      [Mandatory] N/A
* @return    [Mandatory] TEEC_SUCCESS: the initialization was successful.
						 Another error code from Return Code Constants : initialization was not successful.
* @details   [Mandatory] N/A
* @since     [Optional]
* @exception [Optional]
* @throw     [Optional]
* @code      [Mandatory] N/A
* @endcode   [Mandatory] N/A
* @see       [Mandatory] N/A
*/
TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context);

/**
* @brief     [Mandatory] This function finalizes an initialized TEE Context, closing the connection between the Client
						 Application and the TEE.
* @param     [Mandatory] [in] context: an initialized TEEC_Context structure which is to be finalized.
* @pre       [Mandatory] The Client Application MUST only call this function when all Sessions inside this TEE Context have
						 been closed and all Shared Memory blocks have been released.
* @post      [Mandatory] N/A
* @return    [Mandatory] N/A
* @details   [Mandatory] N/A
* @since     [Optional]
* @exception [Optional]
* @throw     [Optional]
* @code      [Mandatory] N/A
* @endcode   [Mandatory] N/A
* @see       [Mandatory] N/A
*/
void TEEC_FinalizeContext(TEEC_Context *context);

/**
* @brief     [Mandatory] This function registers a block of existing Client Application memory as a block of Shared Memory
						 within the scope of the specified TEE Context, in accordance with the parameters which have been set
						 by the Client Application inside the sharedMem structure. Currently, this API is not supported because
						 Client Application memory can be migragted to physical memory different from orginal physical memory.
* @param     [Mandatory] [in] context: a pointer to an initialized TEE Context
* @param     [Mandatory] [in] sharedMem: a pointer to a Shared Memory structure to register.
* @pre       [Mandatory] The context parameter MUST point to an initialized TEE Context.
* @post      [Mandatory] N/A
* @return    [Mandatory] TEEC_SUCCESS: the registration was successful.
						 TEEC_ERROR_OUT_OF_MEMORY: the registration could not be completed because of a lack of resources.
						 Another error code from Return Code Constants : registration was not successful for another reason.
* @details   [Mandatory] N/A
* @since     [Optional]
* @exception [Optional]
* @throw     [Optional]
* @code      [Mandatory] N/A
* @endcode   [Mandatory] N/A
* @see       [Mandatory] N/A
*/
TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context *context, TEEC_SharedMemory *sharedMem);

/**
* @brief     [Mandatory] This function allocates a new block of memory as a block of Shared Memory within the scope of
						 the specified TEE Context, in accordance with the parameters which have been set by the
						 Client Application inside the sharedMem structure.
* @param     [Mandatory] [in] context: a pointer to an initialized TEE Context.
* @param     [Mandatory] [in,out] sharedMem: a pointer to a Shared Memory structure to allocate
* @pre       [Mandatory] The context parameter MUST point to an initialized TEE Context.
* @post      [Mandatory] N/A
* @return    [Mandatory] TEEC_SUCCESS: the allocation was successful.
						 TEEC_ERROR_OUT_OF_MEMORY: the allocation could not be completed due to resource constraints.
						 Another error code from Return Code Constants : allocation was not successful for another reason.
* @details   [Mandatory] N/A
* @since     [Optional]
* @exception [Optional]
* @throw     [Optional]
* @code      [Mandatory] N/A
* @endcode   [Mandatory] N/A
* @see       [Mandatory] N/A
*/
TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *context, TEEC_SharedMemory *sharedMem);

/**
* @brief     [Mandatory] This function deregisters or deallocates a previously initialized block of Shared Memory.
* @param     [Mandatory] [in] sharedMem: a pointer to a valid Shared Memory structure.
* @pre       [Mandatory] N/A
* @post      [Mandatory] Client Application MUST NOT access memory buffer allocated using TEEC_AllocateSharedMemory
						 after this function has been called.
* @return    [Mandatory] N/A
* @details   [Mandatory] N/A
* @since     [Optional]
* @exception [Optional]
* @throw     [Optional]
* @code      [Mandatory] N/A
* @endcode   [Mandatory] N/A
* @see       [Mandatory] N/A
*/
void TEEC_ReleaseSharedMemory(TEEC_SharedMemory *sharedMem);

/**
* @brief     [Mandatory] This function opens a new Session between the Client Application and the specified Trusted Application.
* @param     [Mandatory] [in] context: a pointer to an initialized TEE Context.
* @param     [Mandatory] [out] session: a pointer to a Session structure to open.
* @param     [Mandatory] [in] destination: a pointer to a structure containing the UUID of the destination Trusted Application.
* @param     [Mandatory] [in] connectionMethod: the method of connection to use.
* @param     [Mandatory] [in] connectionData: any necessary data required to support the connection method chosen.
* @param     [Mandatory] [in] operation: a pointer to an Operation containing a set of Parameters to exchange with
							  the Trusted Application, or NULL if no Parameters are to be exchanged or if the operation cannot
							  be cancelled. Refer to TEEC_InvokeCommand for more details.
* @param     [Mandatory] [out] returnOrigin: a pointer to a variable which will contain the return origin. This field may be NULL
							   if the return origin is not needed.
* @pre       [Mandatory]
* @post      [Mandatory]
* @return    [Mandatory] TEEC_SUCCESS: the session was successfully opened.
						 Return code different from TEEC_SUCCESS : the session opening failed.
* @details   [Mandatory] N/A
* @since     [Optional]
* @exception [Optional]
* @throw     [Optional]
* @code      [Mandatory] N/A
* @endcode   [Mandatory] N/A
* @see       [Mandatory] N/A
*/
TEEC_Result TEEC_OpenSession(TEEC_Context *context, TEEC_Session *session, const TEEC_UUID *destination, uint32_t connectionMethod, const void *connectionData, TEEC_Operation *operation, uint32_t *returnOrigin);

/**
* @brief     [Mandatory] This function opens a new Session between the Client Application and the specified Trusted Application.
* @param     [Mandatory] [in] context: a pointer to an initialized TEE Context.
* @param     [Mandatory] [out] session: a pointer to a Session structure to open.
* @param     [Mandatory] [in] destination: a pointer to a structure containing the UUID of the destination Trusted Application.
* @param     [Mandatory] [in] connectionMethod: the method of connection to use.
* @param     [Mandatory] [in] connectionData: any necessary data required to support the connection method chosen.
* @param     [Mandatory] [in] operation: a pointer to an Operation containing a set of Parameters to exchange with
							  the Trusted Application, or NULL if no Parameters are to be exchanged or if the operation cannot
							  be cancelled. Refer to TEEC_InvokeCommand for more details.
* @param     [Mandatory] [out] returnOrigin: a pointer to a variable which will contain the return origin. This field may be NULL
							   if the return origin is not needed.
* @pre       [Mandatory]
* @post      [Mandatory]
* @return    [Mandatory] TEEC_SUCCESS: the session was successfully opened.
						 Return code different from TEEC_SUCCESS : the session opening failed.
* @details   [Mandatory] N/A
* @since     [Optional]
* @exception [Optional]
* @throw     [Optional]
* @code      [Mandatory] N/A
* @endcode   [Mandatory] N/A
* @see       [Mandatory] N/A
*/
void TEEC_CloseSession(TEEC_Session *session);

/**
* @brief     [Mandatory] This function invokes a Command within the specified Session.
* @param     [Mandatory] [in] session: the open Session in which the command will be invoked.
* @param     [Mandatory] [in] commandID: the identifier of the Command within the Trusted Application to invoke.
							  The meaning of each Command Identifier must be defined in the protocol exposed by
							  the Trusted Application
* @param     [Mandatory] [in] operation: a pointer to a Client Application initialized TEEC_Operation structure,
							  or NULL if there is no payload to send or if the Command does not need to support cancellation.
* @param     [Mandatory] [out] returnOrigin: a pointer to a variable which will contain the return origin.
							   This field may be NULL if the return origin is not needed.
* @pre       [Mandatory] N/A
* @post      [Mandatory] N/A
* @return    [Mandatory] TEEC_SUCCESS: the command was successfully incoked.
						 Return code different from TEEC_SUCCESS : the command invoking failed.
* @details   [Mandatory] N/A
* @since     [Optional]
* @exception [Optional]
* @throw     [Optional]
* @code      [Mandatory] N/A
* @endcode   [Mandatory] N/A
* @see       [Mandatory] N/A
*/
TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t commandID, TEEC_Operation *operation, uint32_t *returnOrigin);

/**
* @brief     [Mandatory] This function requests the cancellation of a pending open Session operation or a Command invocation
						 operation. Current TEE Client API implementation doesn't support this API.
* @param     [Mandatory] [in] operation: a pointer to a Client Application instantiated Operation structure.
* @pre       [Mandatory] N/A
* @post      [Mandatory] N/A
* @return    [Mandatory] TEEC_SUCCESS: the operation was successfully cancelled.
						 Return code different from TEEC_SUCCESS : the operation cancellation failed.
* @details   [Mandatory] N/A
* @since     [Optional]
* @exception [Optional]
* @throw     [Optional]
* @code      [Mandatory] N/A
* @endcode   [Mandatory] N/A
* @see       [Mandatory] N/A
*/
void TEEC_RequestCancellation(TEEC_Operation *operation);


/**
* @brief   [Mandatory] This function-like macro builds a constant containing four Parameter types for use in the paramTypes
					   field of a TEEC_Operation structure. It accepts four parameters which MUST be taken from the constant
					   values described in Parameter Types.
* @details [Optional]
* @see     [Optional]
*/
#define TEEC_PARAM_TYPES(param0Type, param1Type, param2Type, param3Type) \
	(uint32_t)(((param0Type) & 0x7f) | \
	(((param1Type) & 0x7f) << 8) | \
	(((param2Type) & 0x7f) << 16) | \
	(((param3Type) & 0x7f) << 24))


#ifdef __cplusplus
}
#endif

#endif /* __TEE_CLIENT_API_H__ */
