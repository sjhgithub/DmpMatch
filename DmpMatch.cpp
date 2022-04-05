// DmpMatch.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"

/*
**  ���ļ����ݼ��ص��ڴ� 
*/
LPVOID  LoadFileData(LPCTSTR pFileName, DWORD* pFileSize)
{
    HANDLE hFile;

    hFile = ::CreateFile(pFileName, 
        GENERIC_READ,          // open for reading
        FILE_SHARE_READ,       // share for reading
        NULL,                  // default security
        OPEN_EXISTING,         // existing file only
        FILE_ATTRIBUTE_NORMAL, // normal file
        NULL);
    if ( hFile == INVALID_HANDLE_VALUE )
    {
        return NULL;
    }

    DWORD dwFileSize = ::GetFileSize(hFile, NULL);
    LPVOID pFileBuffer = malloc(dwFileSize);
    if ( pFileBuffer != NULL )
    {
        ::ReadFile(hFile, pFileBuffer, dwFileSize, &dwFileSize, NULL);
    }

    ::CloseHandle(hFile);
    if ( pFileSize != nullptr )
    {
        *pFileSize = dwFileSize;
    }
    return pFileBuffer;
}

/*
**  ���ڴ����ݱ��浽�ļ� 
*/
BOOL   SaveFileData(LPCTSTR pFileName, LPVOID pFileBuffer, DWORD dwFileSize)
{
    HANDLE hFile;

    hFile = ::CreateFile(pFileName,
        GENERIC_WRITE,          // open for writing
        0,                      // do not share
        NULL,                   // default security
        CREATE_ALWAYS,          // overwrite existing
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL);                  // no attr. template

    if ( hFile == INVALID_HANDLE_VALUE )
    {
        return FALSE;
    }

    DWORD dwWriteSize = 0;
    ::WriteFile(hFile, pFileBuffer, dwFileSize, &dwWriteSize, NULL);
    ::CloseHandle(hFile);

    return (dwFileSize == dwWriteSize);
}

/*
**  ��飬���滻(Exe&Dll)�ļ���Ϣ 
*/
BOOL  MatchFileInfo(MINIDUMP_MODULE* pModule, WCHAR* pModuleName, LPCTSTR  pExeFilePath)
{
    CHAR   sFilePath[MAX_PATH];
    CHAR*  pFileName;

    /*
    **  ����ļ��Ƿ���� 
    */
#ifdef _UNICODE
    WideCharToMultiByte(CP_ACP, 0, pExeFilePath, -1, sFilePath, MAX_PATH, NULL, NULL);
#else 
    strcpy(sFilePath, pExeFilePath);
#endif 
    strcat(sFilePath, "\\");

    INT nFileLen = (INT)_tcslen(sFilePath);
    WideCharToMultiByte(CP_ACP, 0, pModuleName, -1, sFilePath + nFileLen, MAX_PATH - nFileLen, NULL, NULL);

    if ( GetFileAttributes(sFilePath) == INVALID_FILE_ATTRIBUTES )
    {
        return FALSE;
    }

    /*
    **  �����ļ���Ϣ 
    */
    sFilePath[nFileLen - 1] = 0;
    pFileName = sFilePath + nFileLen;

    PLOADED_IMAGE pImage = ImageLoad(pFileName, sFilePath);
    if ( pImage == nullptr )
    {
        return FALSE;
    }
    
    DWORD  dwSizeOfImage = pImage->FileHeader->OptionalHeader.SizeOfImage;
    DWORD  dwCheckSum    = pImage->FileHeader->OptionalHeader.CheckSum;
    if ( dwSizeOfImage == pModule->SizeOfImage && dwCheckSum == pModule->CheckSum )
    {
        return FALSE;
    }

    /*
    **  �滻�ļ���Ϣ 
    */
    printf("    �����ļ�: SizeOfImage: 0x%08X CheckSum: 0x%08X  %s\r\n", dwSizeOfImage, dwCheckSum, pFileName);
    //printf("        Old SizeOfImage: 0x%08X CheckSum: 0x%08X\r\n", pModule->SizeOfImage, pModule->CheckSum);
    //printf("        New SizeOfImage: 0x%08X CheckSum: 0x%08X\r\n", dwSizeOfImage, dwCheckSum);
    pModule->SizeOfImage   = dwSizeOfImage;
    pModule->CheckSum      = dwCheckSum;

    return TRUE;
}

/*
**  ����Dmp�ļ� 
*/
void  ParseDmp(LPVOID pDmpBuffer, DWORD dwDmpLength, LPCTSTR  pExeFilePath)
{
    BYTE*  pDmpBuf = (BYTE*)pDmpBuffer;
    BYTE*  pDmpPos = pDmpBuf;
    
    MINIDUMP_HEADER*    pHeader = nullptr;
    MINIDUMP_DIRECTORY* pDirectory = nullptr;
    MINIDUMP_MODULE *   pModule = nullptr;
    
    DWORD  dwDirCount  = 0;
    DWORD  dwDirOffset = 0;

    DWORD  dwModuleSize   = 0;
    DWORD  dwModuleOffset = 0;
    DWORD  dwModuleCount  = 0;

    /*
    **  1. �ļ�ͷ 
    */
    pHeader = (MINIDUMP_HEADER*)pDmpPos;
    
    dwDirCount  = pHeader->NumberOfStreams;
    dwDirOffset = pHeader->StreamDirectoryRva;

    /*
    **  2. �ļ�Ŀ¼ 
    */
    pDmpPos = pDmpBuf + dwDirOffset;
    for ( DWORD dd = 0; dd < dwDirCount; dd++ )
    {
        pDirectory = (MINIDUMP_DIRECTORY*)pDmpPos;
        if ( pDirectory->StreamType == ModuleListStream )
        {
            // ���ҡ�Module�� 
            dwModuleSize   = pDirectory->Location.DataSize;
            dwModuleOffset = pDirectory->Location.Rva;
            break;
        }

        pDmpPos += sizeof(MINIDUMP_DIRECTORY);
    }

    if ( dwModuleOffset == 0 )
    {
        return ;
    }

    /*
    **  3. ģ���б�.
    */
    pDmpPos = pDmpBuf + dwModuleOffset;
    dwModuleCount = *((DWORD*)pDmpPos);  pDmpPos += sizeof(DWORD);

    for ( DWORD mm = 0; mm < dwModuleCount; mm++ )
    {
        pModule = (MINIDUMP_MODULE *)pDmpPos;

        WCHAR* pModuleName = (WCHAR*)(pDmpBuf + pModule->ModuleNameRva + sizeof(DWORD));
        WCHAR* pNamePos = wcsrchr(pModuleName, '\\');
        if (pNamePos != nullptr)
        {
            pModuleName = pNamePos + 1;
        }

        MatchFileInfo(pModule, pModuleName, pExeFilePath);

        pDmpPos += sizeof(MINIDUMP_MODULE);
    }
}

/*
**  ʹ�ð��� 
*/
void  PrintHelp()
{
    _tprintf(_T("\r\n"));
    _tprintf(_T("����Dmp�ļ�����������ļӿǳ����ļ���Ϣ(Exe&Dll)���޸�Ϊδ�ӿǵĳ����ļ���Ϣ��\r\n"));
    _tprintf(_T("\r\n"));
    _tprintf(_T("DmpMatch.exe <Dmp�ļ�> <δ�ӿǳ����ļ���>\r\n"));
    _tprintf(_T("    ����1�� Dmp�ļ���ȫ·�����ƣ�\r\n"));
    _tprintf(_T("    ����2�� δ�ӿǵĳ����ļ��У�\r\n"));
    _tprintf(_T("\r\n"));
}

int _tmain(int argc, _TCHAR* argv[])
{
    if ( argc < 3 )
    {
        PrintHelp();
        return -1;
    }

    LPCTSTR  pDmpFileName = argv[1];
    LPCTSTR  pExeFilePath = argv[2];
    _tprintf(_T("\r\n"));
    _tprintf(_T("Dmp�ļ��� %s\r\n"), pDmpFileName);
    _tprintf(_T("\r\n"));

    /*
    **  ����dmp�ļ� 
    */
    LPVOID  pDmpBuffer = NULL;
    DWORD   nDmpLength = 0;
    pDmpBuffer = LoadFileData(pDmpFileName, &nDmpLength);
    if ( pDmpBuffer == nullptr )
    {
        _tprintf(_T("����Dmp�ļ�ʧ�ܣ�"));
        _tprintf(_T("\r\n"));
        return -1;
    }

    /*
    **  ����Dmp�ļ� 
    */
    ParseDmp(pDmpBuffer, nDmpLength, pExeFilePath);

    /*
    **  ������dmp�ļ� 
    */
    TCHAR szNewDumpFile[MAX_PATH];
    _tcscpy(szNewDumpFile, pDmpFileName);
    _tcscpy(_tcsrchr(szNewDumpFile, '.'), _T("_new.dmp"));
    SaveFileData(szNewDumpFile, pDmpBuffer, nDmpLength);
    
    /*
    **  �ͷ���Դ 
    */
    free(pDmpBuffer);
    _tprintf(_T("\r\n"));
    return 0;
}

