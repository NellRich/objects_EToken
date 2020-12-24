#include "stdlib.h"
#include "stdio.h"
#include "include\eTPkcs11.h"
#include <windows.h>
#include "base64.h"
#include <iostream>

using namespace std;

void init();
void leave(const char*);
static CK_ULONG GetFirstSlotId();
static bool ReadFromFile(const char* fileName, CK_BYTE_PTR* pkfile, DWORD* pkfileSize);
static bool CreatePKFromBlob(CK_SESSION_HANDLE hSession, CK_BYTE_PTR key, int keySize);
static bool CreateFileFromBlob(CK_SESSION_HANDLE hSession, CK_BYTE_PTR file, DWORD fileSize, const char* label);
static bool ExportingFile(CK_SESSION_HANDLE hSession, CK_BYTE_PTR* file, DWORD* fileSize);
static void ReadFromToken(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hLabel, CK_BYTE_PTR* label, DWORD* labelSize, CK_ATTRIBUTE ValueTemplate);

//Глобальные переменные
CK_FUNCTION_LIST_PTR   pFunctionList=NULL;
CK_C_GetFunctionList   pGFL    = 0;
bool                   wasInit = false; 

void init()
{
// Загружаем dll
  HINSTANCE hLib = LoadLibraryA("etpkcs11.DLL");
  if (hLib == NULL)
  {
    leave ("Cannot load DLL.");
  }
// Ищем точку входа для C_GetFunctionList
  (FARPROC&)pGFL= GetProcAddress(hLib, "C_GetFunctionList");
  if (pGFL == NULL) 
  {
    leave ("Cannot find GetFunctionList().");
  }
//Берем список функций
  if (CKR_OK != pGFL(&pFunctionList))
  {
    leave ("Can't get function list. \n");
  }
// Инициализируем библиотеку PKCS#11
  if (CKR_OK != pFunctionList->C_Initialize (0))
  {
    leave ("C_Initialize failed...\n");
  }                 
  wasInit = true;      
}

static void leave(const char * message)
{
  if (message) printf("%s ", message);
  if(wasInit)
  {
// Закрываем библиотеку PKCS#11
		if (CKR_OK != pFunctionList->C_Finalize(0))
		{
			printf ("C_Finalize failed...\n");
		}
	wasInit = false;
  }
	exit(message ? -1 : 0 );
}

/* Extracts the private key blob from pem */
static void GetPKBlob(CK_BYTE_PTR pk		// pem файл
						   , int pkSize					// Размер файла
						   , CK_BYTE_PTR* subject			// Ука-за-тель на раскодированный закр. ключ
						   , int* subjectSize				// Размер закр. ключа
						   ) 
{
	unsigned int i,size=0,count=0;
	unsigned char* current = pk;
	unsigned char* start;
	unsigned char* end;
	*subject = NULL;               
	*subjectSize = 0;
//находим начало base64 данных
	while (current[0] !='-') *current++; 
	while (current[0] =='-') *current++;
	while (current[0] !='-') *current++;
	while (current[0] =='-') *current++;
	start = ++current;
	while (current[0] !='-') 
	{
		if ((current[0] =='\n') || (current[0] =='-')) count++;
		*current++;
	}
	end = current;
	size = (int)(end-start)-count;
//создаем новый массив, без мешуры
	BYTE *newbyte = new BYTE[size];
	current=start;
	for (i = 0; i < size; i++)
	{
		if (current[0] =='\n') *current++;
		newbyte[i]=(BYTE)current[0];
		*current++;
	}
	*subject = base64_decode((char*)newbyte,size, (unsigned int*)subjectSize);				   
}

static bool ReadFromFile(const char* fileName, CK_BYTE_PTR* pkfile, DWORD* pkfileSize) 
{
    HANDLE hFile = CreateFileA(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    *pkfileSize = GetFileSize(hFile, NULL);
    *pkfile = new byte[*pkfileSize];
    DWORD n;
    return ReadFile(hFile, *pkfile, *pkfileSize, &n, NULL);
}

static void ReadFromToken(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hLabel, CK_BYTE_PTR* value, DWORD* valueSize, CK_ATTRIBUTE ValueTemplate)
{
	int rv = pFunctionList->C_GetAttributeValue(hSession, hLabel, &ValueTemplate, 1);

	if (rv) 
	{
		leave("Cannot read data from the eToken");
	}

	*valueSize = ValueTemplate.ulValueLen;
	*value = new BYTE[*valueSize];
	ValueTemplate.pValue = *value;
	rv = pFunctionList->C_GetAttributeValue(hSession, hLabel, &ValueTemplate, 1);

	if (rv) 
	{
		leave("Cannot read data from the eToken");
	}
} 

static bool CreateFileFromBlob(CK_SESSION_HANDLE hSession, CK_BYTE_PTR file, DWORD fileSize, const char* label) 
{
    CK_OBJECT_HANDLE hObject;
    CK_OBJECT_CLASS your_class = CKO_DATA;
    CK_BBOOL token = CK_TRUE;
    CK_ATTRIBUTE templateArray[] = 
    {
        { CKA_CLASS, &your_class, sizeof(your_class) },
        { CKA_TOKEN, &token, sizeof(token) }, 
        { CKA_LABEL, (void*)label, 40 }, 
        { CKA_APPLICATION, NULL, NULL }, 
        { CKA_VALUE, file, fileSize }
    };

    auto sizeOfTemplate = sizeof(templateArray) / sizeof(CK_ATTRIBUTE);
    CK_RV rv = pFunctionList->C_CreateObject(hSession, templateArray, sizeOfTemplate, &hObject);
    if (rv) 
    {
		std::cout << "Error when creating object\n";
        return false;
    }
    return true;
}

static bool ReadDataFromFile(const char* fileName, CK_BYTE_PTR* data, DWORD* dataSize) 
{
	cout << "Создаем дескриптор файла...\n";
    HANDLE file = CreateFileA(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(file == INVALID_HANDLE_VALUE){
		return false;
    }
    cout << "Посчитали размер файла...\n";
    DWORD size = GetFileSize(file, NULL);
	if (size == INVALID_FILE_SIZE){
		return false;
    }
    cout << "Создаем указатель на массив с данными сертификата...\n";
    *data = new BYTE[size];
    if (ReadFile(file, *data, size, dataSize, NULL) == 0){
		delete[] *data;
		CloseHandle(file);
		return false;
    }
	CloseHandle(file);
	return true;
}

static void ImportPrivateKey(const char* fileName, const char* password)
{
	CK_BYTE_PTR		pkfile = NULL;
	DWORD			pkfileSize;
	CK_BYTE_PTR		subject = NULL;
	int						subjSize;

	// Read the pem file
	cout << "Идет считывание файла...\n";
	if (ReadDataFromFile(fileName, &pkfile, &pkfileSize)) {
		printf ("Файл не прочитался\n");
		return;
	}

	// decode base64 and extract the private key blob
	GetPKBlob((unsigned char*)pkfile, pkfileSize, &subject, &subjSize);

	// Find connected token
	CK_SESSION_HANDLE hSession;

	// login to token
	pFunctionList->C_OpenSession(GetFirstSlotId(), CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
	pFunctionList->C_Login(hSession, CKU_USER, (LPBYTE)password, strlen(password));

	// Import the private key to the token
	if (!CreatePKFromBlob(hSession, subject, subjSize)) cout << "Ключ успешно импор-тирован\n";
	else cout << "Ключ не импортирован\n";

	// Close session
	pFunctionList->C_Logout(hSession);
	pFunctionList->C_CloseSession(hSession);

	if (pkfile) {
		delete[] pkfile;
	}
}

bool CreatePKFromBlob(CK_SESSION_HANDLE hSession, CK_BYTE_PTR key, int keySize) 
{
	if (key[0] != 0x30) return false; //неверный формат
	BYTE* modulus, *pubE, *privE, *p1, *p2, *e1, *e2, *coeff; //компоненты закр. ключа
	int modulusL, pubEL, privEL, p1L, p2L, e1L, e2L, coeffL; //длины компонентов
	int cur = 0;
	while ((key[cur] != 0x02) || ((key[cur + 1] != 0x81) && (key[cur + 1] != 0x82))) 
	{
		cur++;
	}
	cur++;
	if (key[cur] == 0x81) 
	{
		modulusL = key[cur + 1]; 
		modulus = key + cur + 2; 
		if (key[cur + 2] == 0) 
		{
			modulusL--; 
			modulus++; 
			cur++;
		} 
		cur = cur + 2 + modulusL;
	} 
	if (key[cur] == 0x82) 
	{
		modulusL = key[cur + 1] << 8 | key[cur + 2]; 
		modulus = key + cur + 3;
		if (key[cur + 3] == 0) 
		{
			modulusL--; 
			modulus++; 
			cur++;
		} 
		cur = cur + 3 + modulusL;
	} 
	if (key[cur] != 0x02) 
		return false; 
	    cur++;
	pubEL = key[cur]; 
	pubE = key + cur + 1; 
	cur = cur + 1 + pubEL;
	if (key[cur] != 0x02) 
		return false; 
	    cur++;
	if (key[cur] == 0x81) 
	{
		privEL = key[cur + 1]; 
		privE = key + cur + 2; 
		if (key[cur + 2] == 0) 
		{
			privEL--; 
			privE++; 
			cur++;
		} 
		cur = cur + 2 + privEL;
	} 
	if (key[cur] == 0x82) 
	{
		privEL = key[cur + 1] << 8 | key[cur + 2]; 
		privE = key + cur + 3;
		if (key[cur + 3] == 0) 
		{
			privEL--; 
			privE++; 
			cur++;
		} 
		cur = cur + 3 + privEL;
	} 
	if (key[cur] != 0x02) 
		return false; 
	    cur++;
	if ((key[cur] == 0x81) || (key[cur] == 0x80)) cur++;
	p1L = key[cur]; 
	p1 = key + cur + 1; 
	if (key[cur + 1] == 0) 
	{ 
		p1L--; 
		p1++; 
		cur++; 
	} 
	cur = cur + 1 + p1L;
	if (key[cur] != 0x02) 
		return false; 
		cur++;
	if ((key[cur] == 0x81) || (key[cur] == 0x80)) cur++;
	p2L = key[cur]; 
	p2 = key + cur + 1; 
	if (key[cur + 1] == 0) 
	{ 
		p2L--; 
		p2++; 
		cur++; 
	} 
	cur = cur + 1 + p2L;
	if (key[cur] != 0x02) 
		return false; 
		cur++;
	if ((key[cur] == 0x81) || (key[cur] == 0x80)) cur++;
	e1L = key[cur]; 
	e1 = key + cur + 1; 
	if (key[cur + 1] == 0) 
	{ 
		e1L--; 
		e1++; 
		cur++; 
	} 
	cur = cur + 1 + e1L;
	if (key[cur] != 0x02) 
		return false; 
		cur++;
	if ((key[cur] == 0x81) || (key[cur] == 0x80)) cur++;
	e2L = key[cur]; 
	e2 = key + cur + 1; 
	if (key[cur + 1] == 0) 
	{ 
		e2L--; 
		e2++; 
		cur++; 
	} 
	cur = cur + 1 + e2L;
	if (key[cur] != 0x02) 
		return false; 
		cur++;
	if ((key[cur] == 0x81) || (key[cur] == 0x80)) cur++; 
	coeffL = key[cur]; 
	coeff = key + cur + 1; 
	if (key[cur + 1] == 0) 
	{ 
		coeffL--; 
		coeff++; 
	}
	CK_OBJECT_CLASS modAtr = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_BBOOL trueVal = CK_TRUE;
    CK_OBJECT_HANDLE hObject;
	CK_ATTRIBUTE AttributePrivKey[] = 
	{
		{CKA_CLASS, &modAtr, sizeof(modAtr)},
		{CKA_TOKEN, &trueVal, sizeof(trueVal)}, 
		{CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{CKA_MODULUS, modulus, modulusL}, 
		{CKA_PUBLIC_EXPONENT, pubE, pubEL}, 
		{CKA_PRIVATE_EXPONENT, privE, privEL},
		{CKA_PRIME_1, p1, p1L}, 
		{CKA_PRIME_2, p2, p2L}, 
		{CKA_EXPONENT_1, e1, e1L}, 
		{CKA_EXPONENT_2, e2, e2L}, 
		{CKA_COEFFICIENT, coeff, coeffL}, 
	};
	auto sizeOfTemplate = sizeof(AttributePrivKey) / sizeof(CK_ATTRIBUTE);
	pFunctionList->C_CreateObject(hSession, AttributePrivKey, sizeOfTemplate, &hObject);
}

static bool CreateDataFromFile(CK_SESSION_HANDLE hSession, CK_BYTE_PTR file, DWORD fileSize, const char* label) 
{
	CK_BBOOL              trueVal = CK_TRUE;
	CK_OBJECT_CLASS       modAtr = CKO_DATA;

	CK_OBJECT_HANDLE      ObjectData;
	const CK_ULONG        ulCount = 6;
	DWORD                 IdApplication = NULL;
	
	CK_ATTRIBUTE AttributeData[ulCount] = 
	{
		{CKA_CLASS,&modAtr,  sizeof(modAtr)},
		{CKA_TOKEN,&trueVal, sizeof(trueVal)},
		{CKA_VALUE,file,fileSize},
		{CKA_LABEL,(void *) label, sizeof(label)}, 
		{CKA_APPLICATION,&IdApplication,sizeof(IdApplication)}, 
		{CKA_PRIVATE,&trueVal,sizeof(trueVal)},
	};
	pFunctionList->C_CreateObject(hSession, AttributeData, ulCount, &ObjectData);
}

static void ImportFile(const char* fileName,const char* label, const char* password)
{
	CK_BYTE_PTR		file = NULL;
	DWORD			fileSize;
	
	// Read the file
	ReadFromFile(fileName, &file, &fileSize);

	// Find connected token
	CK_SESSION_HANDLE  hSession;
	
	// login to token
	pFunctionList->C_OpenSession(GetFirstSlotId(), CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
	pFunctionList->C_Login(hSession, CKU_USER, (LPBYTE)password, strlen(password));

	// Import file to the token
	if (!CreateFileFromBlob(hSession, file, fileSize, label)) cout << "Загрузка фай-ла прошла успешно" << endl;
	else cout << "Загрузка файла не удалась";

	// Close session
	pFunctionList->C_Logout(hSession);
	pFunctionList->C_CloseSession(hSession);
	
	if (file) {
		delete[] file;
	}
}

static void WriteDataToFile(const char* fileName, CK_BYTE_PTR data, DWORD Size)
{
	HANDLE File;
	File = CreateFileA(fileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, 0, NULL);
	if (File == INVALID_HANDLE_VALUE){
		return;
	}
	DWORD writeByte;
	WriteFile(File, data, Size, &writeByte, NULL);

	CloseHandle(File);
	return;
}

static void ReadLabel(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hLabel, CK_BYTE_PTR* label, DWORD* labelSize) 
{
	CK_ATTRIBUTE      ValueTemplate = {CKA_LABEL,NULL,0};
	int rv = pFunctionList->C_GetAttributeValue(hSession, hLabel, &ValueTemplate, 1);
	if (rv) leave("Невозможно прочитать информацию с eToken");
		*labelSize = ValueTemplate.ulValueLen;
		*label = new BYTE[*labelSize ];
		ValueTemplate.pValue = *label;
		rv = pFunctionList->C_GetAttributeValue(hSession, hLabel, &ValueTemplate, 1);
	if (rv) leave("Невозможно прочитать информацию с eToken");
}

static void ExportFile(const char* fileName, const char* password)
{
	CK_BYTE_PTR		file = NULL;
	DWORD			fileSize;

	CK_OBJECT_CLASS classAttr = CKO_DATA;
	CK_BBOOL trueVal = CK_TRUE;
	CK_ATTRIBUTE Template[] = {
		{CKA_CLASS, &classAttr, sizeof(classAttr)}, 
		{CKA_TOKEN, &trueVal, sizeof(trueVal)},
	};
	CK_ULONG sizeOfTemplate = 2;
	
	// Find connected token
	CK_SESSION_HANDLE  hSession;
	
	// login to token
	pFunctionList->C_OpenSession(GetFirstSlotId(), CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
	pFunctionList->C_Login(hSession, CKU_USER, (LPBYTE)password, strlen(password));

	// Read file from the token and Save the file
	int rv = pFunctionList->C_FindObjectsInit(hSession, Template, sizeOfTemplate);
	if (rv) leave("Информация не найдена");
	
	CK_OBJECT_HANDLE_PTR  ObjList = new CK_OBJECT_HANDLE [10];
	CK_ULONG              nObjMax = 10;
	CK_ULONG              nObjCount;

	pFunctionList->C_FindObjects(hSession, ObjList, nObjMax, &nObjCount);

	CK_OBJECT_HANDLE_PTR  object;
	CK_BYTE_PTR           labelVar = NULL;
	CK_ULONG              labeSizelVar;

	for (int i = 0; i < nObjCount; i++) 
	{
		ReadLabel(hSession, ObjList[i], &labelVar, &labeSizelVar);
			printf("\n");
			for (int j = 0; i < labeSizelVar; j++) {
				printf("%c", labelVar[j]);
			}
			printf("- %d\n", i);
	}
	printf("Номер объекта: ");

	char buf[10];
	gets(buf);
	int numberObj = atoi(buf);

	CK_BYTE_PTR data;
	DWORD dataSize = 0;
		
	CK_ATTRIBUTE Template2[] = {
		{CKA_VALUE,NULL,dataSize}
	};

	pFunctionList->C_GetAttributeValue(hSession, ObjList[numberObj], Template2, 1);
	Template2->pValue = new CK_BYTE[Template2->ulValueLen];

	WriteDataToFile(fileName, (CK_BYTE_PTR)Template2->pValue, Template2->ulValueLen);

	// Close session
	pFunctionList->C_Logout(hSession);
	pFunctionList->C_CloseSession(hSession);
	
	if (file) 
	{
		delete[] file;
	}	
}

static void DeleteData(const char* password)
{
	// Find connected token
	CK_SESSION_HANDLE  hSession;
	
	// login to token
	pFunctionList->C_OpenSession(GetFirstSlotId(), CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
	pFunctionList->C_Login(hSession, CKU_USER, (LPBYTE)password, strlen(password));
	
	// read data and delete selected	
	
	CK_OBJECT_CLASS classAttr = CKO_DATA;
	CK_BBOOL trueVal = CK_TRUE;

	CK_ATTRIBUTE Template[] = 
	{
		{CKA_CLASS,&classAttr,sizeof(classAttr)}, 
		{CKA_TOKEN,&trueVal,sizeof(trueVal)},
	};
	CK_ULONG       sizeOfTemplate = 2;

	int rv = pFunctionList->C_FindObjectsInit(hSession, Template, sizeOfTemplate);
	if (rv) leave("Cannot find data");
	
	CK_OBJECT_HANDLE_PTR ObjList = new CK_OBJECT_HANDLE[10];
	CK_ULONG              nObjMax = 10;
	CK_ULONG              nObjCount;

	pFunctionList->C_FindObjects(hSession, ObjList, nObjMax, &nObjCount);
	
	CK_ATTRIBUTE Label = { CKA_LABEL,NULL,0 };

	for (int i = 0; i < nObjCount; i++)
	{
		CK_BYTE_PTR label = NULL;
		DWORD labelsize = NULL;
		char buf = NULL;

		ReadFromToken(hSession, ObjList[i], &label, &labelsize, Label);
		cout << "Delete object " << label << "? (y/n)\n";
		cin >> buf;
	
		if (buf == 'y')
		{
			pFunctionList->C_DestroyObject(hSession, ObjList[i]);
		}
	}

	// Close session
	pFunctionList->C_Logout(hSession);
	pFunctionList->C_CloseSession(hSession);
}

static CK_ULONG GetFirstSlotId() 
{
	CK_ULONG slotID = -1;
	CK_ULONG ulCount = 0;
	CK_SLOT_ID_PTR pSlotIDs = NULL_PTR;
	CK_ULONG i;
	if (pFunctionList->C_GetSlotList(TRUE, NULL_PTR, &ulCount) == CKR_OK)
	{
		if (ulCount > 0) 
		{
			pSlotIDs = new CK_SLOT_ID[ulCount];
			if ((pFunctionList->C_GetSlotList(TRUE, pSlotIDs, &ulCount)) == CKR_OK) 
			{
				for (i = 0; i < ulCount; i++) 
				{
					CK_SLOT_INFO info;
					if ((pFunctionList->C_GetSlotInfo(pSlotIDs[i], &info)) == CKR_OK) 
					{
						if (info.flags & (CKF_HW_SLOT | CKF_TOKEN_PRESENT)) 
						{
							slotID = pSlotIDs[i];
							break;
						}
					}
				}
			}
		}
	}
	if (pSlotIDs) 
	{
		delete[] pSlotIDs;pSlotIDs = NULL_PTR;
	}
	return slotID;
}


int main()
{
	setlocale(LC_ALL, "rus");
	init();
	int choice;
	char path[100];
	char pass[20];
	char label[50];
	while (true)
	{
		cout << "Выберите действие:"
			<< "\n[0]\tЗакрыть программу;"
			<< "\n[1]\tИмпортировать закрытый ключ;"
			<< "\n[2]\tИмпортировать конфиденциальные данные на токен;"
			<< "\n[3]\tЭкспортировать конфиденциальные данные с токена;"
			<< "\n[4]\tУдалить конфиденциальные данные с токена;\n";
		cin >> choice;
		switch (choice)
		{
			case 0:
			{
				cout << "Выход...";
				return 0;
				break;
			}
			case 1:
			{
				cout << "\nВведите путь: \t";
				cin >> path;
				cout << "\nВведите пароль: \t";
				cin >> pass;
				ImportPrivateKey(path, pass);
				break;
			}
			case 2:
			{
				cout << "\nВведите путь: \t";
				cin >> path;
				cout << "\nВведите имя файла: \t";
				cin >> label;
				cout << "\nВведите пароль: \t";
				cin >> pass;
				ImportFile(path, label, pass);
				break;
			}
			case 3:
			{
				cout << "\nВведите пароль: \t";
				cin >> pass;
				ExportFile(path, pass);
				break;
			}
			case 4:
			{
				cout << "\nВведите пароль: \t";
				cin >> pass;
				DeleteData(pass);
				break;
			}
			default:
			{
				cout << "\nНекорректные данные,пожалуйста,введите еще раз";
			}
		}
}
	system("pause");
	leave(NULL);
	return 0;
}
