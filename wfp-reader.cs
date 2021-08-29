/* Proof of concept - Covert Channel using Windows Filtering Platform 
 * Author: Juan Manuel Fernández (@TheXC3LL)
 * Original: https://adepts.of0x.cc/connectionless-shells/
 */


using System;
using System.Runtime.InteropServices;


namespace wfp_helper
{
    class WFP
    {
        //FWPM_DISPLAY_DATA0 - https://docs.microsoft.com/en-us/windows/win32/api/fwptypes/ns-fwptypes-fwpm_display_data0
        [StructLayout(LayoutKind.Sequential)]
        public struct FWPM_DISPLAY_DATA0
        {
            [MarshalAsAttribute(UnmanagedType.LPWStr)]
            public string name;
            [MarshalAsAttribute(UnmanagedType.LPWStr)]
            public string description;
        }

        //FWPM_SESSION0 - https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0
        [StructLayout(LayoutKind.Sequential)]
        public struct FWPM_SESSION0
        {
            public Guid sessionKey;
            public FWPM_DISPLAY_DATA0 displayData;
            public UInt32 flags;
            public UInt32 txnWaitTimeoutInMSec;
            public uint processId;
            public IntPtr sid;
            [MarshalAsAttribute(UnmanagedType.LPWStr)]
            public string username;
            public bool kernelMode;
        }


        //FWP_IP_VERSION - https://docs.microsoft.com/en-us/windows/win32/api/fwptypes/ne-fwptypes-fwp_ip_version   
        public enum FWP_IP_VERSION
        {
            FWP_IP_VERSION_V4 = 0,
            FWP_IP_VERSION_V6 = 1,
            FWP_IP_VERSION_NONE = 2,
            FWP_IP_VERSION_MAX = 3
        }

        //FWP_BYTE_ARRAY16 - https://docs.microsoft.com/en-us/windows/win32/api/fwptypes/ns-fwptypes-fwp_byte_array16
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct FWP_BYTE_ARRAY16 {
            public fixed byte byteArray16[16];
        }

        //FWP_BYTE_BLOB - https://docs.microsoft.com/en-us/windows/win32/api/fwptypes/ns-fwptypes-fwp_byte_blob
        [StructLayout(LayoutKind.Sequential)]
        public struct FWP_BYTE_BLOB
        {
            public UInt32 size;
            public IntPtr data;
        }

        //FWPM_NET_EVENT_HEADER0 - https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event_header0
        [StructLayout(LayoutKind.Explicit)]
        public struct FWPM_NET_EVENT_HEADER0
        {
            [FieldOffsetAttribute(0)]
            public System.Runtime.InteropServices.ComTypes.FILETIME timeStamp; // 64 bits = 8 bytes
            [FieldOffsetAttribute(8)]
            public UInt32 flags;
            [FieldOffsetAttribute(12)]
            public FWP_IP_VERSION ipVersion;
            [FieldOffsetAttribute(16)]
            public byte ipProtocol;
            [FieldOffsetAttribute(20)]
            public UInt32 localAddrV4;
            [FieldOffsetAttribute(20)]
            public FWP_BYTE_ARRAY16 localAddrv6;
            [FieldOffsetAttribute(36)]
            public UInt32 remoteAddrV4;
            [FieldOffsetAttribute(36)]
            public FWP_BYTE_ARRAY16 remoteAddrv6;
            [FieldOffsetAttribute(52)]
            public UInt16 localPort;
            [FieldOffsetAttribute(54)]
            public UInt16 remotePort;
            [FieldOffsetAttribute(56)]
            UInt32 scopeId;
            [FieldOffsetAttribute(64)]
            public FWP_BYTE_BLOB appId;
            [FieldOffsetAttribute(80)]
            public IntPtr userId;
        }

        //FWPM_NET_EVENT_TYPE - https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ne-fwpmtypes-fwpm_net_event_type
        public enum FWPM_NET_EVENT_TYPE
        {
            FWPM_NET_EVENT_TYPE_IKEEXT_MM_FAILURE = 0,
            FWPM_NET_EVENT_TYPE_IKEEXT_QM_FAILURE = 1,
            FWPM_NET_EVENT_TYPE_IKEEXT_EM_FAILURE = 2,
            FWPM_NET_EVENT_TYPE_CLASSIFY_DROP = 3,
            FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP = 4,
            FWPM_NET_EVENT_TYPE_IPSEC_DOSP_DROP = 5,
            FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW = 6,
            FWPM_NET_EVENT_TYPE_CAPABILITY_DROP = 7,
            FWPM_NET_EVENT_TYPE_CAPABILITY_ALLOW = 8,
            FWPM_NET_EVENT_TYPE_CLASSIFY_DROP_MAC = 9,
            FWPM_NET_EVENT_TYPE_LPM_PACKET_ARRIVAL = 10,
            FWPM_NET_EVENT_TYPE_MAX = 11
        }

        //IPSEC_FAILURE_POINT - https://docs.microsoft.com/en-us/windows/win32/api/ipsectypes/ne-ipsectypes-ipsec_failure_point
        public enum IPSEC_FAILURE_POINT
        {
            IPSEC_FAILURE_NONE = 0,
            IPSEC_FAILURE_ME = 1,
            IPSEC_FAILURE_PEER = 2,
            IPSEC_FAILURE_POINT_MAX = 3
        }

        //IKEEXT_KEY_MODULE_TYPE - https://docs.microsoft.com/en-us/windows/win32/api/iketypes/ne-iketypes-ikeext_key_module_type
        public enum IKEEXT_KEY_MODULE_TYPE
        {
            IKEEXT_KEY_MODULE_IKE = 0,
            IKEEXT_KEY_MODULE_AUTHIP = 1,
            IKEEXT_KEY_MODULE_IKEV2 = 2,
            IKEEXT_KEY_MODULE_MAX = 3
        }

        //IKEEXT_MM_SA_STATE - https://docs.microsoft.com/es-mx/windows/win32/api/Iketypes/ne-iketypes-ikeext_mm_sa_state
        public enum IKEEXT_MM_SA_STATE
        {
            IKEEXT_MM_SA_STATE_NONE = 0,
            IKEEXT_MM_SA_STATE_SA_SENT = 1,
            IKEEXT_MM_SA_STATE_SSPI_SENT = 2,
            IKEEXT_MM_SA_STATE_FINAL = 3,
            IKEEXT_MM_SA_STATE_FINAL_SENT = 4,
            IKEEXT_MM_SA_STATE_COMPLETE = 5,
            IKEEXT_MM_SA_STATE_MAX = 6
        }

        //IKEEXT_SA_ROLE - https://docs.microsoft.com/en-us/windows/win32/api/iketypes/ne-iketypes-ikeext_sa_role
        public enum IKEEXT_SA_ROLE
        {
            IKEEXT_SA_ROLE_INITIATOR = 0,
            IKEEXT_SA_ROLE_RESPONDER = 1,
            IKEEXT_SA_ROLE_MAX = 2
        }

        //IKEEXT_AUTHENTICATION_METHOD_TYPE
        public enum IKEEXT_AUTHENTICATION_METHOD_TYPE
        {
            IKEEXT_PRESHARED_KEY = 0,
            IKEEXT_CERTIFICATE = 1,
            IKEEXT_KERBEROS = 2,
            IKEEXT_ANONYMOUS = 3,
            IKEEXT_SSL = 4,
            IKEEXT_NTLM_V2 = 5,
            IKEEXT_IPV6_CGA = 6,
            IKEEXT_CERTIFICATE_ECDSA_P256 = 7,
            IKEEXT_CERTIFICATE_ECDSA_P384 = 8,
            IKEEXT_SSL_ECDSA_P256 = 9,
            IKEEXT_SSL_ECDSA_P384 = 10,
            IKEEXT_EAP = 11,
            IKEEXT_RESERVED = 12,
            IKEEXT_AUTHENTICATION_METHOD_TYPE_MAX = 13
        }

        //FWPM_NET_EVENT_IKEEXT_MM_FAILURE0 - https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event_ikeext_mm_failure0
        [StructLayoutAttribute(LayoutKind.Sequential)]
        public unsafe struct FWPM_NET_EVENT_IKEEXT_MM_FAILURE0
        {
            public UInt32 failureErrorCode;
            public IPSEC_FAILURE_POINT failurePoint;
            public UInt32 flags;
            public IKEEXT_KEY_MODULE_TYPE keyingModuleType;
            public IKEEXT_MM_SA_STATE mmState;
            public IKEEXT_SA_ROLE saRole;
            public IKEEXT_AUTHENTICATION_METHOD_TYPE mmAuthMethod;
            public fixed byte endCertHash[20];
            public UInt64 mmId;
            public UInt64 mmFilterId;
        }

        // FWPM_NET_EVENT0 - https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event0
        [StructLayout(LayoutKind.Explicit)]
        public struct FWPM_NET_EVENT0
        {
            [FieldOffsetAttribute(0)]
            public FWPM_NET_EVENT_HEADER0 header;
            [FieldOffsetAttribute(88)]
            public FWPM_NET_EVENT_TYPE type;
            [FieldOffsetAttribute(96)]
            public IntPtr ikeMmFailure; //FWPM_NET_EVENT_IKEEXT_MM_FAILURE0 Yes
            [FieldOffsetAttribute(96)]
            public IntPtr ikeQmFailure; // FWPM_NET_EVENT_IKEEXT_QM_FAILURE0 No
            [FieldOffsetAttribute(96)]
            public IntPtr ikeEmFailure; // FWPM_NET_EVENT_IKEEXT_EM_FAILURE0 No
            [FieldOffsetAttribute(96)]
            public IntPtr classifyDrop; // FWPM_NET_EVENT_CLASSIFY_DROP0 No
            [FieldOffsetAttribute(96)]
            public IntPtr ipsecDrop; // FWPM_NET_EVENT_IPSEC_KERNEL_DROP0 No
            [FieldOffsetAttribute(96)]
            public IntPtr idpDrop; // FWPM_NET_EVENT_IPSEC_DOSP_DROP0 No
        }

        // FWPM_NET_EVENT_ENUM_TEMPLATE0 - https://docs.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_net_event_enum_template0
        [StructLayout(LayoutKind.Sequential)]
        public struct FWPM_NET_EVENT_ENUM_TEMPLATE0
        {
            public System.Runtime.InteropServices.ComTypes.FILETIME startTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME endTime;
            public UInt32 numFilterConditions;
            public IntPtr filterCondition;
        }


        //LARGE_INTEGER - https://stackoverflow.com/questions/3053578/how-to-declare-ularge-integer-in-c
        [StructLayout(LayoutKind.Explicit, Size = 8)]
       public struct LARGE_INTEGER
        {
            [FieldOffsetAttribute(0)] public Int64 QuadPart;
            [FieldOffsetAttribute(0)] public Int32 LowPart;
            [FieldOffsetAttribute(4)] public Int32 HighPart;
        }
        // Consts
        const uint RPC_C_AUTHN_WINNT = 0xa;
        const uint ERROR_SUCCESS = 0x0;
        const uint FWPM_SESSION_FLAG_DYNAMIC = 0x1;
        const uint INFINITE = 0xffffffff;
        const uint IPPROTO_UDP = 0x11;

        // DLL imports
        [DllImport("kernel32")]
        public static extern void GetSystemTimeAsFileTime(ref System.Runtime.InteropServices.ComTypes.FILETIME lpSystemTimeAsFileTime);

        [DllImportAttribute("FWPUClnt.dll", EntryPoint = "FwpmEngineOpen0")] //https://docs.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0
        public static extern uint FwpmEngineOpen0(
            [InAttribute()][MarshalAsAttribute(UnmanagedType.LPWStr)] string serverName,
            uint authnService,
            [InAttribute()] IntPtr authIdentity,
            [InAttribute()] ref FWPM_SESSION0 session,
            ref IntPtr engineHandle);

        [DllImportAttribute("FWPUClnt.dll", EntryPoint = "FwpmNetEventCreateEnumHandle0")] //https://docs.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmneteventcreateenumhandle0
        public static extern uint FwpmNetEventCreateEnumHandle0(
            [InAttribute()] IntPtr engineHandle,
            ref  FWPM_NET_EVENT_ENUM_TEMPLATE0 enumTemplate,
            ref IntPtr enumHandle);

        [DllImportAttribute("FWPUClnt.dll", EntryPoint = "FwpmNetEventEnum0")]//https://docs.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmneteventenum0
        public static extern uint FwpmNetEventEnum0(
            [InAttribute()] IntPtr engineHandle,
            [InAttribute()] IntPtr enumHandle,
            UInt32 numEntriesRequested,
            [InAttribute()] ref IntPtr entries, //***
            [InAttribute()] ref UInt32 numEntriesReturned
            );

        // Stack overflow dixit
        public static string ConvertHex(string hexString)
        {
            try
            {
                string ascii = string.Empty;

                for (int i = 0; i < hexString.Length; i += 2)
                {
                    string hs = string.Empty;

                    hs = hexString.Substring(i, 2);
                    ulong decval = Convert.ToUInt64(hs, 16);
                    long deccc = Convert.ToInt64(hs, 16);
                    char character = Convert.ToChar(deccc);
                    ascii += character;

                }

                return ascii;
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }

            return string.Empty;
        }
        // Stack overflow dixit
        public static string Reverse(string s)
        {
            char[] charArray = s.ToCharArray();
            Array.Reverse(charArray);
            return new string(charArray);
        }
        public static void Main(string[] args)
        {
            System.Runtime.InteropServices.ComTypes.FILETIME ft;
            ft.dwHighDateTime = 0;
            ft.dwLowDateTime = 0;


            Console.WriteLine("\t-=[Proof of concept - Covert Channel using Windows Filtering Platform]=-\n\n");

            while (true)
            {
                IntPtr engineHandle = IntPtr.Zero;
                FWPM_SESSION0 session = new FWPM_SESSION0();
                session.flags = FWPM_SESSION_FLAG_DYNAMIC;
                uint ret = 0;


                ret = FwpmEngineOpen0(null, RPC_C_AUTHN_WINNT, IntPtr.Zero, ref session, ref engineHandle);
                if (ret != ERROR_SUCCESS)
                {
                    throw new Exception("[-] FwpmEngineOpen0 Failed!");
                }

                FWPM_NET_EVENT_ENUM_TEMPLATE0 enumTempl = new FWPM_NET_EVENT_ENUM_TEMPLATE0();
                LARGE_INTEGER ulTime;

                GetSystemTimeAsFileTime(ref enumTempl.endTime);
                ulTime.QuadPart = 0;
                ulTime.LowPart = enumTempl.endTime.dwLowDateTime;
                ulTime.HighPart = enumTempl.endTime.dwHighDateTime;
                ulTime.QuadPart -= 100 * 10000000;
                enumTempl.startTime.dwLowDateTime = ulTime.LowPart;
                enumTempl.startTime.dwHighDateTime = ulTime.HighPart;
                enumTempl.numFilterConditions = 0;

                IntPtr enumHandle = IntPtr.Zero;

                ret = FwpmNetEventCreateEnumHandle0(engineHandle, ref enumTempl, ref enumHandle);
                if (ret != ERROR_SUCCESS)
                {
                    throw new Exception("[-] FwpmNetEventCreateEnumHandle0 Failed!");
                }

                IntPtr entries = IntPtr.Zero;
                UInt32 numEntries = 0;
                ret = FwpmNetEventEnum0(engineHandle, enumHandle, INFINITE, ref entries, ref numEntries);
                if (ret != ERROR_SUCCESS)
                {
                    throw new Exception("[-] FwpmNetEventEnum0 Failed!");
                }
                if (numEntries > 0)
                {
                    FWPM_NET_EVENT0[] eventEntries = new FWPM_NET_EVENT0[numEntries];
                    for (int i = 0; i < numEntries; i++)
                    {
                        IntPtr tmpPtr = Marshal.ReadIntPtr(entries, i * IntPtr.Size);
                        eventEntries[i] = (FWPM_NET_EVENT0)Marshal.PtrToStructure(tmpPtr, typeof(FWPM_NET_EVENT0));
                        if (
                            eventEntries[i].header.ipVersion == FWP_IP_VERSION.FWP_IP_VERSION_V4 //Ipv4
                            && eventEntries[i].header.ipProtocol == IPPROTO_UDP // UDP
                            && eventEntries[i].header.localPort == 123 // Target Port
                            && (eventEntries[i].header.timeStamp.dwHighDateTime > ft.dwHighDateTime // Is a newer event
                                || (eventEntries[i].header.timeStamp.dwHighDateTime == ft.dwHighDateTime && eventEntries[i].header.timeStamp.dwLowDateTime > ft.dwLowDateTime)
                                )
                            )
                        {
                            //Save time reference
                            ft.dwHighDateTime = eventEntries[i].header.timeStamp.dwHighDateTime;
                            ft.dwLowDateTime = eventEntries[i].header.timeStamp.dwLowDateTime;

                            Console.Write("{0}", Reverse(ConvertHex(eventEntries[i].header.remotePort.ToString("X"))));
                        }
                    }
                }
            }

        }

    }
}
