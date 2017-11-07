/*
2016/11/2 23:11  
By Wen Xingbeng
*/

/*  --------------- A demo------------
	pid_hash_content_t demo; int i=0;
	for(i=0;i<16;i++){
		demo.NID[i]=i;
	}
	for(i=0;i<20;i++){
		demo.SID[i]=i;
	}
	demo.SK=66;
	demo.PID=122;
	demo.PIDs=88;
	printf("RES=%d\n",pid_hash(demo));	
*/

#include <stdio.h>
typedef struct{
	uint8_t NID[16];	
	uint8_t SID[20];
	uint32_t SK;		
	uint32_t PID;
	uint32_t PIDs;
}pid_hash_content_t;

#define my_jhash_mix(a, b, c) do { \
	a -= b; a -= c; a ^= (c>>13); \
	b -= c; b -= a; b ^= (a<<8); \
	c -= a; c -= b; c ^= (b>>13); \
	a -= b; a -= c; a ^= (c>>12); \
	b -= c; b -= a; b ^= (a<<16); \
	c -= a; c -= b; c ^= (b>>5); \
	a -= b; a -= c; a ^= (c>>3); \
	b -= c; b -= a; b ^= (a<<10); \
	c -= a; c -= b; c ^= (b>>15); \
} while (0)

static inline uint32_t my_jhash_3words(uint32_t a,uint32_t b,uint32_t c,uint32_t INVITAL,uint32_t KEY)
{
	a +=KEY;
	b +=KEY;
	c +=INVITAL;
	my_jhash_mix(a, b, c);
	return c;
}

static inline uint32_t pid_hash(pid_hash_content_t content)
{
	uint32_t INVITAL=0;
	uint32_t *a,*b,*c,*content_point_32bit;
	int i=0;
	content_point_32bit=(uint32_t *)(&content);
	uint32_t KEY=content.SK;
	for(i=0;i<4;i++)
	{
		a=content_point_32bit++;
		b=content_point_32bit++;
		c=content_point_32bit++;	
		INVITAL=my_jhash_3words(*a,*b,*c,INVITAL,KEY);
	}
	return INVITAL;
}
