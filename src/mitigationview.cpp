//
// mitigationsview.cpp
//
// Simple tool to show the process mitigations policy
//

#include "stdafx.h"

// stringification
#define xstr(s) str(s)
#define str(s) #s

void print_error(const char *desc, DWORD errcode) {
    LPTSTR errorText = NULL;

    FormatMessage(
        // use system message tables to retrieve error text
        FORMAT_MESSAGE_FROM_SYSTEM
        // allocate buffer on local heap for error text
        |FORMAT_MESSAGE_ALLOCATE_BUFFER
        // Important! will fail otherwise, since we're not 
        // (and CANNOT) pass insertion parameters
        |FORMAT_MESSAGE_IGNORE_INSERTS,  
        NULL,    // unused with FORMAT_MESSAGE_FROM_SYSTEM
        errcode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&errorText,  // output 
        0, // minimum size for output buffer
        NULL);   // arguments - see note 

    if (errorText != NULL) {
        if (desc == NULL) desc = "Error";
        if (errorText[strlen(errorText)-1] == '\n') errorText[strlen(errorText)-1] = '\0';
        if (errorText[strlen(errorText)-1] == '\r') errorText[strlen(errorText)-1] = '\0';
        fprintf(stderr, "%s: %08X: %s\n", desc, errcode, errorText);
        // release memory allocated by FormatMessage()
        LocalFree(errorText);
    }
}

#define GET_MITIGATION(proc, p, b, s) \
    if (!GetProcessMitigationPolicy((proc), (p), (b), (s))) { \
        if (0) { print_error(str(p), GetLastError()); } \
    } else

void print_mitigations(HANDLE hProc) {

    PROCESS_MITIGATION_DEP_POLICY                       dep = {0};
    PROCESS_MITIGATION_ASLR_POLICY                      aslr = {0};
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY              dynamic_code_policy = {0};
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY       strict_handle_check = {0};
    PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY       system_call_disable = {0};
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY   extension_point_disable = {0};
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY        control_flow_guard_policy = {0};
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY          binary_signature_policy = {0};
    PROCESS_MITIGATION_FONT_DISABLE_POLICY              font_disable_policy = {0};
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY                image_load_policy = {0};
    PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY         user_shadow_stack_policy = {0};

    GET_MITIGATION(hProc, ProcessDEPPolicy, &dep, sizeof(dep)) {
        printf("ProcessDEPPolicy\n");
        printf("    Enable                                     %u\n", dep.Enable);
        printf("    DisableAtlThunkEmulation                   %u\n", dep.DisableAtlThunkEmulation);
        printf("    Permanent                                  %u\n", dep.Permanent);
    }

    GET_MITIGATION(hProc, ProcessASLRPolicy, &aslr, sizeof(aslr)) {
        printf("\nProcessASLRPolicy\n");
        printf("    EnableBottomUpRandomization                %u\n", aslr.EnableBottomUpRandomization);
        printf("    EnableForceRelocateImages                  %u\n", aslr.EnableForceRelocateImages);
        printf("    EnableHighEntropy                          %u\n", aslr.EnableHighEntropy);
        printf("    DisallowStrippedImages                     %u\n", aslr.DisallowStrippedImages);
    }
    
    GET_MITIGATION(hProc, ProcessDynamicCodePolicy, &dynamic_code_policy, sizeof(dynamic_code_policy)) {
        printf("\nProcessDynamicCodePolicy\n");
        printf("    ProhibitDynamicCode                        %u\n", dynamic_code_policy.ProhibitDynamicCode);
        printf("    AllowThreadOptOut                          %u\n", dynamic_code_policy.AllowThreadOptOut);
        printf("    AllowRemoteDowngrade                       %u\n", dynamic_code_policy.AllowRemoteDowngrade);
        printf("    AuditProhibitDynamicCode                   %u\n", dynamic_code_policy.AuditProhibitDynamicCode);
    }

    GET_MITIGATION(hProc, ProcessStrictHandleCheckPolicy, &strict_handle_check, sizeof(strict_handle_check)) {
        printf("\nProcessStrictHandleCheckPolicy\n");
        printf("    RaiseExceptionOnInvalidHandleReference     %u\n", strict_handle_check.RaiseExceptionOnInvalidHandleReference);
        printf("    HandleExceptionsPermanentlyEnabled         %u\n", strict_handle_check.HandleExceptionsPermanentlyEnabled);
    }

    GET_MITIGATION(hProc, ProcessSystemCallDisablePolicy, &system_call_disable, sizeof(system_call_disable)) {
        printf("\nProcessSystemCallDisablePolicy\n");
        printf("    DisallowWin32kSystemCalls                  %u\n", system_call_disable.DisallowWin32kSystemCalls);
        printf("    AuditDisallowWin32kSystemCalls             %u\n", system_call_disable.AuditDisallowWin32kSystemCalls);
    }

    GET_MITIGATION(hProc, ProcessExtensionPointDisablePolicy, &extension_point_disable, sizeof(extension_point_disable)) {
        printf("\nProcessExtensionPointDisablePolicy\n");
        printf("    DisableExtensionPoints                     %u\n", extension_point_disable.DisableExtensionPoints);
    }

    GET_MITIGATION(hProc, ProcessControlFlowGuardPolicy, &control_flow_guard_policy, sizeof(control_flow_guard_policy)) {
        printf("\nProcessControlFlowGuardPolicy\n");
        printf("    EnableControlFlowGuard                     %u\n", control_flow_guard_policy.EnableControlFlowGuard);
        printf("    EnableExportSuppression                    %u\n", control_flow_guard_policy.EnableExportSuppression);
        printf("    StrictMode                                 %u\n", control_flow_guard_policy.StrictMode);
        //printf("    EnableXfg                                  %u\n", control_flow_guard_policy.EnableXfg);
        //printf("    EnableXfgAuditMode                         %u\n", control_flow_guard_policy.EnableXfgAuditMode);
    }

    GET_MITIGATION(hProc, ProcessSignaturePolicy, &binary_signature_policy, sizeof(binary_signature_policy)) {
        printf("\nProcessSignaturePolicy\n");
        printf("    MicrosoftSignedOnly                        %u\n", binary_signature_policy.MicrosoftSignedOnly);
        printf("    StoreSignedOnly                            %u\n", binary_signature_policy.StoreSignedOnly);
        printf("    MitigationOptIn                            %u\n", binary_signature_policy.MitigationOptIn);
        printf("    AuditMicrosoftSignedOnly                   %u\n", binary_signature_policy.AuditMicrosoftSignedOnly);
        printf("    AuditStoreSignedOnly                       %u\n", binary_signature_policy.AuditStoreSignedOnly);
    }
    
    GET_MITIGATION(hProc, ProcessFontDisablePolicy, &font_disable_policy, sizeof(font_disable_policy)) {
        printf("\nProcessFontDisablePolicy\n");
        printf("    DisableNonSystemFonts                      %u\n", font_disable_policy.DisableNonSystemFonts);
        printf("    AuditNonSystemFontLoading                  %u\n", font_disable_policy.AuditNonSystemFontLoading);
    }
    
    GET_MITIGATION(hProc, ProcessImageLoadPolicy, &image_load_policy, sizeof(image_load_policy)) {
        printf("\nProcessImageLoadPolicy\n");
        printf("    NoRemoteImages                             %u\n", image_load_policy.NoRemoteImages);
        printf("    NoLowMandatoryLabelImages                  %u\n", image_load_policy.NoLowMandatoryLabelImages);
        printf("    PreferSystem32Images                       %u\n", image_load_policy.PreferSystem32Images);
        printf("    AuditNoRemoteImages                        %u\n", image_load_policy.AuditNoRemoteImages);
        printf("    AuditNoLowMandatoryLabelImages             %u\n", image_load_policy.AuditNoLowMandatoryLabelImages);
    }
    
    GET_MITIGATION(hProc, ProcessUserShadowStackPolicy, &user_shadow_stack_policy, sizeof(user_shadow_stack_policy)) {
        printf("\nProcessUserShadowStackPolicy\n");
        printf("    EnableUserShadowStack                      %u\n", user_shadow_stack_policy.EnableUserShadowStack);
        printf("    AuditUserShadowStack                       %u\n", user_shadow_stack_policy.AuditUserShadowStack);
        printf("    SetContextIpValidation                     %u\n", user_shadow_stack_policy.SetContextIpValidation);
        printf("    AuditSetContextIpValidation                %u\n", user_shadow_stack_policy.AuditSetContextIpValidation);
        printf("    EnableUserShadowStackStrictMode            %u\n", user_shadow_stack_policy.EnableUserShadowStackStrictMode);
        printf("    BlockNonCetBinaries                        %u\n", user_shadow_stack_policy.BlockNonCetBinaries);
        printf("    BlockNonCetBinariesNonEhcont               %u\n", user_shadow_stack_policy.BlockNonCetBinariesNonEhcont);
        printf("    AuditBlockNonCetBinaries                   %u\n", user_shadow_stack_policy.AuditBlockNonCetBinaries);
        printf("    CetDynamicApisOutOfProcOnly                %u\n", user_shadow_stack_policy.CetDynamicApisOutOfProcOnly);
        printf("    SetContextIpValidationRelaxedMode          %u\n", user_shadow_stack_policy.SetContextIpValidationRelaxedMode);
    }
}

void usage(const char *p) {
    printf("usage: %s <pid>\n", p);
}

int main(int argc, char* argv[]) {
    DWORD pid = 0;
    HANDLE hProc;

    if (argc != 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    pid = strtoul(argv[1], NULL, 0);
    if (pid == 0) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
    if (hProc == NULL) {
        print_error("OpenProcess", GetLastError());
        return EXIT_FAILURE;
    }

    print_mitigations(hProc);

    CloseHandle(hProc);
	return EXIT_SUCCESS;
}

