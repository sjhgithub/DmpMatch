// DmpMatch.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

/*
**  将文件数据加载到内存 
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
**  将内存数据保存到文件 
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
**  检查，并替换(Exe&Dll)文件信息 
*/
BOOL  MatchFileInfo(MINIDUMP_MODULE* pModule, WCHAR* pModuleName, LPCTSTR  pExeFilePath)
{
    CHAR   sFilePath[MAX_PATH];
    CHAR*  pFileName;

    /*
    **  检查文件是否存在 
    */
#ifdef _UNICODE
    WideCharToMultiByte(CP_ACP, 0, pExeFilePath, -1, sFilePath, MAX_PATH, NULL, NULL);
#else 
    strcpy(sFilePath, pExeFilePath);
#endif 
    strcat(sFilePath, "\\");

    INT nFileLen = (INT)strlen(sFilePath);
    WideCharToMultiByte(CP_ACP, 0, pModuleName, -1, sFilePath + nFileLen, MAX_PATH - nFileLen, NULL, NULL);

    if ( GetFileAttributesA(sFilePath) == INVALID_FILE_ATTRIBUTES )
    {
        return FALSE;
    }

    /*
    **  加载文件信息 
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
    **  替换文件信息 
    */
    printf("    更新文件: SizeOfImage: 0x%08X CheckSum: 0x%08X  %s\r\n", dwSizeOfImage, dwCheckSum, pFileName);
    //printf("        Old SizeOfImage: 0x%08X CheckSum: 0x%08X\r\n", pModule->SizeOfImage, pModule->CheckSum);
    //printf("        New SizeOfImage: 0x%08X CheckSum: 0x%08X\r\n", dwSizeOfImage, dwCheckSum);
    pModule->SizeOfImage   = dwSizeOfImage;
    pModule->CheckSum      = dwCheckSum;

    return TRUE;
}

/*
**  解析Dmp文件 
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
    **  1. 文件头 
    */
    pHeader = (MINIDUMP_HEADER*)pDmpPos;
    
    dwDirCount  = pHeader->NumberOfStreams;
    dwDirOffset = pHeader->StreamDirectoryRva;

    /*
    **  2. 文件目录 
    */
    pDmpPos = pDmpBuf + dwDirOffset;
    for ( DWORD dd = 0; dd < dwDirCount; dd++ )
    {
        pDirectory = (MINIDUMP_DIRECTORY*)pDmpPos;
        if ( pDirectory->StreamType == ModuleListStream )
        {
            // 查找“Module” 
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
    **  3. 模块列表.
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
**  使用帮助 
*/
void  PrintHelp()
{
    _tprintf(_T("\r\n"));
    _tprintf(_T("解析Dmp文件，将其关联的加壳程序文件信息(Exe&Dll)，修改为未加壳的程序文件信息！\r\n"));
    _tprintf(_T("\r\n"));
    _tprintf(_T("DmpMatch.exe <Dmp文件> <未加壳程序文件夹>\r\n"));
    _tprintf(_T("    参数1： Dmp文件的全路径名称；\r\n"));
    _tprintf(_T("    参数2： 未加壳的程序文件夹！\r\n"));
    _tprintf(_T("\r\n"));
}

int _tmain(int argc, _TCHAR* argv[])
{
    system("@chcp 65001>nul");

    if ( argc < 3 )
    {
        PrintHelp();
        return -1;
    }

    LPCTSTR  pDmpFileName = argv[1];
    LPCTSTR  pExeFilePath = argv[2];
    _tprintf(_T("\r\n"));
    _tprintf(_T("Dmp文件： %s\r\n"), pDmpFileName);
    _tprintf(_T("\r\n"));

    /*
    **  加载dmp文件 
    */
    LPVOID  pDmpBuffer = NULL;
    DWORD   nDmpLength = 0;
    pDmpBuffer = LoadFileData(pDmpFileName, &nDmpLength);
    if ( pDmpBuffer == nullptr )
    {
        _tprintf(_T("加载Dmp文件失败！"));
        _tprintf(_T("\r\n"));
        return -1;
    }

    /*
    **  解析Dmp文件 
    */
    ParseDmp(pDmpBuffer, nDmpLength, pExeFilePath);

    /*
    **  保存新dmp文件 
    */
    TCHAR szNewDumpFile[MAX_PATH];
    _tcscpy(szNewDumpFile, pDmpFileName);
    _tcscpy(_tcsrchr(szNewDumpFile, '.'), _T("_new.dmp"));
    SaveFileData(szNewDumpFile, pDmpBuffer, nDmpLength);
    
    /*
    **  释放资源 
    */
    free(pDmpBuffer);
    _tprintf(_T("\r\n"));
    return 0;
}

