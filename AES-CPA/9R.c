#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <Windows.h>

#define DIR "C:\\Users\\louxsoen\\Documents\\부채널연구\\AES CPA\\"
#define traceFN "a.traces"
#define ctFN "ciphertext.txt"

#define startpt	60001
#define endpt 73200

#define MUL2(a) (a<<1)^(a&0x80?0x1b:0)
#define MUL3(a) MUL2(a)^a
#define MUL4(a) MUL2((MUL2(a)))
#define MUL8(a) MUL2((MUL2((MUL2(a)))))
#define MUL9(a) (MUL8(a))^(a)
#define MULB(a) (MUL8(a))^(MUL2(a))^(a)
#define MULD(a) (MUL8(a))^(MUL4(a))^(a)
#define MULE(a) (MUL8(a))^(MUL4(a))^(MUL2(a))


typedef unsigned char u8;

static u8 RSBOX[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

u8 ISR(u8 S[16])
{
	u8 temp;
	temp = S[13]; S[13] = S[9]; S[9] = S[5]; S[5] = S[1]; S[1] = temp;
	temp = S[2]; S[2] = S[10]; S[10] = temp; temp = S[6]; S[6] = S[14]; S[14] = temp;
	temp = S[3]; S[3] = S[7]; S[7] = S[11]; S[11] = S[15]; S[15] = temp;
}
u8 IM(u8 S[16])
{
	u8 temp[16];

	for (int i = 0; i < 16; i += 4)
	{
		temp[i] = MULE(S[i]) ^ MULB(S[i + 1]) ^ MULD(S[i + 2]) ^ MUL9(S[i + 3]);
		temp[i + 1] = MUL9(S[i]) ^ MULE(S[i + 1]) ^ MULB(S[i + 2]) ^ MULD(S[i + 3]);
		temp[i + 2] = MULD(S[i]) ^ MUL9(S[i + 1]) ^ MULE(S[i + 2]) ^ MULB(S[i + 3]);
		temp[i + 3] = MULB(S[i]) ^ MULD(S[i + 1]) ^ MUL9(S[i + 2]) ^ MULE(S[i + 3]);
	}
	S[0] = temp[0]; S[1] = temp[1]; S[2] = temp[2]; S[3] = temp[3];
	S[4] = temp[4]; S[5] = temp[5]; S[6] = temp[6]; S[7] = temp[7];
	S[8] = temp[8]; S[9] = temp[9]; S[10] = temp[10]; S[11] = temp[11];
	S[12] = temp[12]; S[13] = temp[13]; S[14] = temp[14]; S[15] = temp[15];
}

void SR(u8 S[16])
{
	u8 temp;
	temp = S[1]; S[1] = S[5]; S[5] = S[9]; S[9] = S[13]; S[13] = temp;
	temp = S[2]; S[2] = S[10]; S[10] = temp; temp = S[6]; S[6] = S[14]; S[14] = temp;
	temp = S[15]; S[15] = S[11]; S[11] = S[7]; S[7] = S[3]; S[3] = temp;
}

void M(u8 S[16])
{
	u8 temp[16];

	for (int i = 0; i < 16; i += 4) // temp를 쓰는 이유 : mixcolumns시 state 원본값 손실
	{
		temp[i] = MUL2(S[i]) ^ MUL3(S[i + 1]) ^ S[i + 2] ^ S[i + 3];
		temp[i + 1] = S[i] ^ MUL2(S[i + 1]) ^ MUL3(S[i + 2]) ^ S[i + 3];
		temp[i + 2] = S[i] ^ S[i + 1] ^ MUL2(S[i + 2]) ^ MUL3(S[i + 3]);
		temp[i + 3] = MUL3(S[i]) ^ S[i + 1] ^ S[i + 2] ^ MUL2(S[i + 3]);
	}
	S[0] = temp[0]; S[1] = temp[1]; S[2] = temp[2]; S[3] = temp[3];
	S[4] = temp[4]; S[5] = temp[5]; S[6] = temp[6]; S[7] = temp[7];
	S[8] = temp[8]; S[9] = temp[9]; S[10] = temp[10]; S[11] = temp[11];
	S[12] = temp[12]; S[13] = temp[13]; S[14] = temp[14]; S[15] = temp[15];
}

void gotoxy(int x, int y)
{
	COORD Pos = { x - 1, y - 1 };

	SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), Pos);
}
void pprt(u8 S[16])
{
	puts("");
	for (int i = 0; i < 4; i++)
	{
		for (int k = 0; k < 4; k++)
		{
			printf("%02X ", S[i + k * 4]);
		}
		puts("");
	}
	puts("");
}
int main()
{
	u8** CT = NULL;
	u8** CT2 = NULL;
	u8		temp[34];
	u8		iv, hw_iv; // 데이터의 해밍웨이터
	u8		R10[16] = { 0xf2, 0x98, 0x3f, 0x40, 0x30, 0xed, 0xf6, 0x33, 0x04, 0x91, 0x10, 0x3f, 0xd1, 0xb1, 0x3f, 0xa1 };	 // 추출한 마스터키
	u8		R9[16] = { 0x73, 0x8D, 0x34, 0x43, 0xC2, 0x75, 0xC9, 0x73, 0x34, 0x7C, 0xE6, 0x0C, 0xD5, 0x20, 0x2F, 0x9E };
	u8		R9S[16];
	double	maxCorr; // 상관계수 최대값(PEAK마다 바)
	double* corr;	// 코렐레이션 값
	double	HW;	  // 해밍웨이트의 합, 전력량의 합
	double	HW_2, * WT_2; // 해밍웨이트 제곱들의 합, 전력량의 제곱들의 합
	double* hw_wt;		// 해밍 x 전력의 합
	double* WT; // 실제 전력값들의 합, 전력값들 제곱의 합
	double	a, b, c;
	float** WT_data;  // 파동을 전체 저장할 데이터
	int		TraceNum, TraceLength;
	int		key, maxkey;
	int		x, y;	      // plaintext 파일 가져올 때 쓰이는 변수
	int		i, j, k;	  // 반복문에 쓰이는 변수
	char	buf[256];	  // 파일 디렉토리를 덮어 쓸 임시값
	double	cur, all;
	FILE* rfp, * wfp;
	printf("\n    IA&AI Sec LAB");
	// DATA
	sprintf(buf, "%s%s", DIR, traceFN);
	rfp = fopen(buf, "rb");
	if (rfp == NULL)
		printf("%s 파일 읽기 오류", traceFN);

	fread(&TraceLength, sizeof(int), 1, rfp); // TraceLength를 int 크키 만큼 한번 읽는다 (4bytes)
	fread(&TraceNum, sizeof(int), 1, rfp);	  // TraceNum을 int 크기 만큼 한번 읽는다 (4bytes)
	// DATA 동적 할당
	WT_data = (float**)calloc(TraceNum, sizeof(float*));
	for (i = 0; i < TraceNum; i++)
		WT_data[i] = (float*)calloc(TraceLength, sizeof(float));

	// DATA 
	for (i = 0; i < TraceNum; i++) {
		fread(WT_data[i], sizeof(float), TraceLength, rfp);
	}
	fclose(rfp);

	// PLAINTEXT
	sprintf(buf, "%s%s", DIR, ctFN);
	rfp = fopen(buf, "r"); // read binary가 아님. 무조건 r
	if (rfp == NULL)
		printf("%s 파일 읽기 오류", ctFN);

	CT = (u8**)calloc(TraceNum, sizeof(u8*)); // 역참조 : 값 넣어주면 안정화
	for (i = 0; i < TraceNum; i++)
		CT[i] = (u8*)calloc(16, sizeof(u8));

	CT2 = (u8**)calloc(TraceNum, sizeof(u8*)); // 역참조 : 값 넣어주면 안정화
	for (i = 0; i < TraceNum; i++)
		CT2[i] = (u8*)calloc(16, sizeof(u8));

	for (i = 0; i < TraceNum; i++) {
		fread(temp, sizeof(char), 33, rfp);
		for (j = 0; j < 16; j++) {
			x = temp[2 * j];
			y = temp[2 * j + 1];

			if (x >= 'a' && x <= 'z') x = x - 'a' + 10;
			else if (x >= 'A' && x <= 'Z') x = x - 'A' + 10;
			else if (x >= '0' && x <= '9') x -= '0';

			if (y >= 'a' && y <= 'z') y = y - 'a' + 10;
			else if (y >= 'A' && y <= 'Z') y = y - 'A' + 10;
			else if (y >= '0' && y <= '9') y -= '0';

			CT[i][j] = x * 16 + y;
			CT2[i][j] = x * 16 + y;
		}
	}



	corr = (double*)calloc(TraceLength, sizeof(double));
	WT = (double*)calloc(TraceLength, sizeof(double));
	WT_2 = (double*)calloc(TraceLength, sizeof(double));
	hw_wt = (double*)calloc(TraceLength, sizeof(double));

	for (i = 0; i < TraceNum; i++)
	{
		for (j = startpt; j < endpt; j++) {
			WT[j] += WT_data[i][j];
			WT_2[j] += WT_data[i][j] * WT_data[i][j];
		}
	}

	for (j = 0; j < TraceNum; j++) {

		for (int a = 0; a < 16; a++)
		{
			CT[j][a] = RSBOX[CT[j][a] ^ R10[a]];
		}
		ISR(CT[j]);							// 여기까지 CT'


		IM(CT[j]);
		ISR(CT[j]);
	}

	for (int i = 0; i < 16; i++)
	{
		maxCorr = 0;
		maxkey = 0;
		for (key = 0; key < 256; key++) {
			HW = 0;
			HW_2 = 0;
			memset(hw_wt, 0, sizeof(double) * TraceLength);
			for (j = 0; j < TraceNum; j++) { 
				
				/* for (int a = 0; a < 16; a++)
				{	
					CT[j][a] = RSBOX[CT[j][a] ^ R10[a]];
				}
				ISR(CT[j]);							// 여기까지 CT'
				

				IM(CT[j]);
				ISR(CT[j]);*/
				// "ISR(IM(CT))" + ISR(IM(KEY)) 
				
				iv = RSBOX[CT[j][i] ^ key];
				hw_iv = 0;
				for (k = 0; k < 8; k++) hw_iv += ((iv >> k) & 1);

				HW += hw_iv;
				HW_2 += hw_iv * hw_iv; 

				for (k = startpt; k < endpt; k++) {
					hw_wt[k] += hw_iv * WT_data[j][k];
				}
			}

			for (j = startpt; j < endpt; j++) { // 상관계수 구하는 곳

				a = (double)TraceNum * hw_wt[j] - WT[j] * HW;
				b = sqrt((double)TraceNum * WT_2[j] - WT[j] * WT[j]);
				c = sqrt((double)TraceNum * HW_2 - HW * HW);

				//printf("%lf %lf %lf\n", a, b, c);

				corr[j] = a / (b * c);
				if (fabs(corr[j]) > maxCorr) {
					maxkey = key;
					maxCorr = fabs(corr[j]);
				}

			}
			gotoxy(25, 25);
			printf("\rProgress %.1lf%%  |  %02dth Block : %.1lf%%", (((double)key / 255) * 100 / 16) + (100 / 16 * i), i, ((double)key / 255) * 100);

			sprintf(buf, "%sct\\%02d_%02X.ct", DIR, i, key);
			fflush(stdout);
			wfp = fopen(buf, "wb");
			if (wfp == NULL)
				printf("블록 쓰기 에러\n");
			fwrite(corr, sizeof(double), TraceLength, wfp);
			fclose(wfp);

		}
		gotoxy(1, 1);
		gotoxy(1, i + 5);
		R9[i] = maxkey;
		printf("%d Block Before IM : %02X, Corr : %lf\n", i, maxkey, maxCorr);
	}
	ISR(R9);
	IM(R9);
	puts("");
	for (int i = 0; i < 16; i++)	printf("%02X", R9[i]);
	puts(""); 

	free(CT);
	free(hw_wt);
	free(WT);
	free(WT_2);
	free(WT_data);
	free(corr);
}