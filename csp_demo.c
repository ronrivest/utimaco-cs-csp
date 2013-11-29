#undef UNICODE					// ## Not Yet

#define _WIN32_WINNT 0x0400

#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include <ctype.h>
#include <malloc.h>
#include <process.h>
#include <windows.h>
#include <wincrypt.h>

/******************************************************************************
 *
 * Definitions
 *
 ******************************************************************************/
#ifndef ALG_SID_SHA_256
#define ALG_SID_SHA_256           12
#endif

#define CALG_RIPEMD160            (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_RIPEMD160)

#ifndef CALG_SHA_256
#define CALG_SHA_256              (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
#endif


#define UTIMACO_CS_PROV           "Utimaco CryptoServer CSP"

/******************************************************************************
 *
 * Globals
 *
 ******************************************************************************/
unsigned char Text[] = 
    "Oh, say can you see by the dawn's early light" \
    "What so proudly we hailed at the twilights last gleaming?" \
    "Whose broad stripes and broght stars thru the perilous fight," \
    "O'er the ramparts we watched were so gallantly streaming?" \
    "And the rocket's red glare, the bombs bursting in air," \
    "Gave proof through the night that our flag was still there." \
    "Oh, say does that star-spangled banner yet wave" \
    "O'er the land of the free and the home of the brave?";

/******************************************************************************
 *
 * Macros
 *
 ******************************************************************************/
#define CLEANUP(x) { err = (x); goto cleanup; }


/******************************************************************************
 *
 * xtrace
 *
 ******************************************************************************/
static void xtrace(char *txt,void *data,int len)
{
  static char hex[]="0123456789abcdef";

  int  a;
  char *x;
  char *dt;
  int  adr=0;
  char buff1[40];
  char buff2[20];
  
  if(txt) printf("%s:\n",txt);

  dt=(char *)data;
  while(len>0) 
  {
	  x=buff1;
	  for(a=0;a<16 && a<len;a++) 
    {
		  if((a&3)==0) *x++ = ' ';
		  if((a&7)==0) *x++ = ' ';
		  *x++ = hex[(dt[a]>>4)&15];
		  *x++ = hex[dt[a]&15];
		}
	  *x=0;

	  x=buff2;
	  for(a=0;a<16 && a<len;a++) 
    {
		  *x++ = (dt[a]>' ' && dt[a]<0x7f) ? dt[a] : ' ';
		}
	  *x=0;

	  printf("%6x%-38s |%-16s|\n",adr,buff1,buff2);
	  len-=16;
	  dt+=16;
	  adr+=16;
	}
}

/******************************************************************************
 *
 * writefile
 *
 ******************************************************************************/
static int writefile(char *file, unsigned char *p_data, unsigned int l_data)
{
  FILE *fp;

  if ((fp = fopen(file, "wb")) == NULL)
    return -1;

  fwrite(p_data, 1, l_data, fp);
  fclose(fp);

  return 0;
}

/******************************************************************************
 *
 * readfile
 *
 ******************************************************************************/
static int readfile(char *file, unsigned char *p_data, unsigned int l_max_data, unsigned int *p_l_data)
{
  FILE *fp;
   
  *p_l_data = 0;

  if ((fp = fopen(file, "rb")) == NULL)
    return -1;

  *p_l_data = fread(p_data, 1, l_max_data, fp);

  fclose(fp);

  return 0;
}

/******************************************************************************
 *
 * reverse
 *
 ******************************************************************************/
void reverse(unsigned char *p_x, unsigned int len)
{
  unsigned char *p_start = p_x;
  unsigned char *p_end = p_x + len - 1;
  unsigned char c;

  while(p_end > p_start)
  {
    c = *p_start;
    *p_start++ = *p_end;
    *p_end-- = c;
  }
}

/******************************************************************************
 *
 * GetLastErrorText
 *
 ******************************************************************************/
LPTSTR GetLastErrorText()
{
  DWORD   dwRet;

  static char szBuf[1024];

  DWORD   dwSize = sizeof(szBuf);
  LPTSTR  pszTemp = NULL; 
  int     err = GetLastError();

  dwRet = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |FORMAT_MESSAGE_ARGUMENT_ARRAY,
                        NULL,
                        err,
                        LANG_NEUTRAL,
                        (LPTSTR)&pszTemp,
                        0,
                        NULL );

  if (dwRet == 0)
  {
    sprintf(szBuf, "GetLastError() returned 0x%08x", err);
  }
  else 
  {    
    //remove cr and newline character
    pszTemp[strlen(pszTemp)-2] = 0;
    
    sprintf(szBuf, "%s (0x%08x)", pszTemp, err);
  }
  
  if (pszTemp)
    LocalFree((HLOCAL)pszTemp);

  return szBuf;
}

/******************************************************************************
 *
 * ListAlgos 
 *
 ******************************************************************************/
int ListAlgos(HCRYPTPROV hProv)
{    
  BYTE        pbData[1024];
  DWORD       cbData;
  DWORD       dwFlags;

  CHAR        *pszAlgType = NULL;  
  CHAR        szName[100];
  
  PROV_ENUMALGS     *p_algo;
  PROV_ENUMALGS_EX  *p_algo_ex;

  printf("\nEnumerating the supported algorithms:\n\n");
  printf("\tAlgid      Bits      Type        Name         Algorithm\n");
  printf("\t                                 Length          Name\n\n");  

  dwFlags = CRYPT_FIRST;

  while(1)
  {  
    cbData = sizeof(pbData);

    if(CryptGetProvParam(hProv, PP_ENUMALGS, pbData, &cbData, dwFlags) == FALSE)
      break;
  
    dwFlags = 0;

    p_algo = (PROV_ENUMALGS*)pbData;
          
    switch(GET_ALG_CLASS(p_algo->aiAlgid)) 
    {
      case ALG_CLASS_DATA_ENCRYPT: pszAlgType = "Encrypt  ";
                                   break;
      case ALG_CLASS_HASH:         pszAlgType = "Hash     ";
                                   break;
      case ALG_CLASS_KEY_EXCHANGE: pszAlgType = "Exchange ";
                                   break;
      case ALG_CLASS_SIGNATURE:    pszAlgType = "Signature";
                                   break;
      default:                     pszAlgType = "Unknown  ";
    }

    memset(szName, 0, sizeof(szName));
    strncpy(szName, p_algo->szName, p_algo->dwNameLen);    
  
    printf("\t%8.8xh    %-4d    %s     %-2d          %s\n", 
           p_algo->aiAlgid, 
           p_algo->dwBitLen, 
           pszAlgType, 
           p_algo->dwNameLen, 
           szName);
  }

  printf("\nEnumerating the supported algorithms:\n\n");
  printf("\tAlgid      Len       Type        Name         Algorithm\n");
  printf("\t                                 Length          Name\n\n");  

  dwFlags = CRYPT_FIRST;

  while(1)
  {  
    cbData = sizeof(pbData);

    if(CryptGetProvParam(hProv, PP_ENUMALGS_EX, pbData, &cbData, dwFlags) == FALSE)
      break;
  
    dwFlags = 0;

    p_algo_ex = (PROV_ENUMALGS_EX*)pbData;   
          
    switch(GET_ALG_CLASS(p_algo_ex->aiAlgid)) 
    {
      case ALG_CLASS_DATA_ENCRYPT: pszAlgType = "Encrypt  ";
                                   break;
      case ALG_CLASS_HASH:         pszAlgType = "Hash     ";
                                   break;
      case ALG_CLASS_KEY_EXCHANGE: pszAlgType = "Exchange ";
                                   break;
      case ALG_CLASS_SIGNATURE:    pszAlgType = "Signature";
                                   break;
      default:                     pszAlgType = "Unknown  ";
    }
  
    memset(szName, 0, sizeof(szName));
    strncpy(szName, p_algo_ex->szName, p_algo_ex->dwNameLen);    
  
    printf("\t%8.8xh    %-4d    %s     %-2d          %s\n", 
           p_algo_ex->aiAlgid, 
           p_algo_ex->dwDefaultLen, 
           pszAlgType, 
           p_algo_ex->dwNameLen, 
           szName);
  }

  return 0;
}  

/******************************************************************************
 *
 * main
 *
 ******************************************************************************/
int __cdecl main(int cArg, char *rgszArg[])
{       
  int             err             = 0;
  char            szProv[]        = UTIMACO_CS_PROV;
  char            *pszContainer   = NULL;
  DWORD           dwFlags         = 0 
                                //| CRYPT_MACHINE_KEYSET 
                                //| CRYPT_VERIFYCONTEXT
                                  ;
  
  HCRYPTPROV      hProv           = 0;    
  HCRYPTKEY       hSignKey        = 0;
  HCRYPTKEY       hPubKey         = 0;
  HCRYPTKEY       hHash           = 0;
  
  unsigned char   hash[20];
  unsigned int    l_hash          = 0;
  unsigned char   blob[1024];
  unsigned int    l_blob          = 0;
  unsigned char   data[1024];
  unsigned int    l_data          = 0;
  unsigned char   sign[1024];
  unsigned int    l_sign          = 0;		

  //-----------------------------------------------------------------------------
  // acquire context
  //-----------------------------------------------------------------------------
  if (CryptAcquireContext(&hProv, pszContainer, szProv, PROV_RSA_FULL, dwFlags) == FALSE)
	{
    printf("CryptAcquireContext failed:\n%s\n", GetLastErrorText() );    
		goto cleanup;
	}
	
	ListAlgos(hProv);
  
  //-----------------------------------------------------------------------------
  // create new signature key
  //-----------------------------------------------------------------------------
#if 1
  if (CryptGenKey(hProv, AT_SIGNATURE, (2048<<16) | CRYPT_EXPORTABLE, &hSignKey) == FALSE)
	{
    printf("CryptGenKey [AT_SIGNATURE] failed:\n%s\n", GetLastErrorText() );    
    goto cleanup;
	}
#else
  if (CryptGetUserKey(hProv, AT_SIGNATURE, &hSignKey) == FALSE)
	{
    printf("CryptGetUserKey [AT_SIGNATURE] failed:\n%s\n", GetLastErrorText() );
    goto cleanup;
	}
#endif
  
  //-----------------------------------------------------------------------------
  // export signature key
  //-----------------------------------------------------------------------------
  l_blob = sizeof(blob);

  if (CryptExportKey(hSignKey, (HCRYPTKEY)NULL, PUBLICKEYBLOB, 0, blob, &l_blob) == FALSE)  
  {
    printf("CryptExportKey failed:\n%s\n", GetLastErrorText() );    
	  goto cleanup;
  }

  //-----------------------------------------------------------------------------
  // sign data
  //-----------------------------------------------------------------------------  
  if ((err = readfile("data", data, sizeof(data), &l_data)) != 0)
	{
		l_data = sizeof(Text);
		memcpy(data, Text, l_data);		
	}
	
  if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash) == FALSE)
  {
    printf("CryptCreateHash failed:\n%s\n", GetLastErrorText() );    
	  goto cleanup;
  }
  
  if (CryptHashData(hHash, data, l_data, 0) == FALSE)
  {
    printf("CryptHashData failed:\n%s\n", GetLastErrorText() );    
	  goto cleanup;
  }

  l_hash = sizeof(hash);

  if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &l_hash, 0) == FALSE)
  {
    printf("CryptGetHashParam failed:\n%s\n", GetLastErrorText() );    
	  goto cleanup;
  }

  xtrace("hash", hash, l_hash);  

  l_sign = sizeof(sign);

  if (CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, sign, &l_sign) == FALSE)
  {
    printf("CryptSignHash failed:\n%s\n", GetLastErrorText() );    
	  goto cleanup;
  }  

  xtrace("sign", sign, l_sign);  
     
  //-----------------------------------------------------------------------------
  // import public key
  //-----------------------------------------------------------------------------    		
  if (CryptImportKey(hProv, blob, l_blob, (HCRYPTKEY)NULL, 0, &hPubKey) == FALSE)  
  {
    printf("CryptImportKey failed:\n%s\n", GetLastErrorText() );    
	  goto cleanup;
  }     

  //-----------------------------------------------------------------------------
  // verify signature
  //-----------------------------------------------------------------------------    		

#if 1
  if (CryptVerifySignature(hHash, sign, l_sign, hPubKey, NULL, 0) == FALSE)
  {
    printf("CryptVerifySignature failed:\n%s\n", GetLastErrorText());
	  goto cleanup;
  }  

#else
  reverse(sign, l_sign);

  if (CryptEncrypt(hPubKey, NULL, TRUE, 0, sign, &l_sign, sizeof(sign)) == FALSE)
  {
    printf("CryptEncrypt failed:\n%s\n", GetLastErrorText());
	  goto cleanup;
  }

  xtrace("plain sign", sign, l_sign);
    
#endif
  
cleanup:          
  CryptDestroyHash(hHash);
  CryptDestroyKey(hPubKey);
  CryptDestroyKey(hSignKey);

  CryptReleaseContext(hProv, 0);      
}

