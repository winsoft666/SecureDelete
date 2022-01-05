#include <stdio.h>
#include <string>
#include "SecureDelete.h"

bool CreateTestFile(const std::wstring& filePath) {
    FILE* f = NULL;
    _wfopen_s(&f, filePath.c_str(), L"wb");
    if (!f)
        return false;
    std::string strTxt = "hello, my name is tim, my id is ";
    for (int i = 0; i < 1000; i++) {
        std::string strWrite = strTxt + std::to_string(i) + "\r\n";
        if (strWrite.length() != fwrite(strWrite.c_str(), 1, strWrite.length(), f)) {
            fclose(f);
            return false;
        }
    }
    fclose(f);
    return true;
}

int main()
{
    SecureDelete sdel;
    printf("Secure Delete Support: %d\n", sdel.isSecureSupported());

    std::wstring filePath = L"23ar65.txt";
    if (CreateTestFile(filePath)) {
        printf("Create test file success, press any key to secure delete this file\n");
        getchar();
        if (sdel.deleteFile(filePath.c_str(), 1)) {
            printf("Secure delete file success\n");
        }
        else {
            printf("Secure delete file failed\n");
        }
    }

#if 0
    std::wstring directoryPath = L""; // TODO: set path
    if(sdel.deleteDirectory(directoryPath.c_str())) {
        printf("Secure delete directory success\n");
    }
    else {
        printf("Secure delete directory failed\n");
    }
#endif

    return 0;
}
