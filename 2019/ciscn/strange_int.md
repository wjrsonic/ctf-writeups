# strange_int

������һ���������ǰ��512�ֽ�loder��BIOS�����ڴ棬loader�Ѻ���Ĳ���Ҳ�����ڴ棬���ú�IDT/GDT��ִ�г���ת���뱣��ģʽ���۲�GDT����ֵ������cs��ds��ָ����0x00000000�����Կ��԰�image.bin��ͷ512�ֽ��е����Ͻ�IDA������


![Alt text](images/strange_int_1.png)


ͬʱʹ��bochs�Գ�����е��ԡ��ڵ��Թ����з��֣�ÿ�����е�0x64ʱ���жϺŶ��ᱻ�ı䡣�������ٷ���sub_68()���ȡ0x0d48[edi*4]����ֵ���ݴ��޸��жϺš���bochs�в鿴IDT��


![Alt text](images/strange_int_2.png)


����IDA�в鿴�ж���������Ӧ�ĵ�ַ��


![Alt text](images/strange_int_3.png)


�������Ǹ�VM��sub_68()ÿ�λ��12���ֽڣ���һ��DWORD��8λ��Ӧָ���루���жϺţ����ڶ�������DWORD�ǲ����������ڴ�0x0b64~0x0b77��5��DWORD��VM�ļĴ�����0x0b78������VM�ĳ������������ָ����Ϊ0X2f�����"correct")��0x30(���"wrong")ʱ�����������

д�˸��ű���0x0d48��ʼ����Ӧ�ļ�+0f48h��������dump����������Ӧ���ָ���ÿ��VMָ�����Ϊ��
(a=(DWORD\*)0x0b64, b=(DWORD\*)0x0d48)

```
int_num=0x21, ecx=0x0, eax=0x81  a[0]=0x81
int_num=0x27, ecx=0x1, eax=0x1   xor a[1],a[1]
int_num=0x24, ecx=0x1, eax=0x1   b[a[1]]=a[1]
int_num=0x23, ecx=0x2, eax=0x0   a[2]=b[a[0]]
int_num=0x22, ecx=0x3, eax=0x2   a[3]=a[2]
int_num=0x21, ecx=0x4, eax=0x8   mov a[4],0x8
int_num=0x28, ecx=0x3, eax=0x4   a[3]=a[3]<<(a[4]&0xff)
int_num=0x27, ecx=0x2, eax=0x3   xor a[2],a[3]
int_num=0x28, ecx=0x3, eax=0x4   a[3]=a[3]<<(a[4]&0xff)
int_num=0x27, ecx=0x2, eax=0x3   xor a[2],a[3]
int_num=0x28, ecx=0x3, eax=0x4   a[3]=a[3]<<(a[4]&0xff)
int_num=0x27, ecx=0x2, eax=0x3   xor a[2],a[3]
int_num=0x27, ecx=0x3, eax=0x3   xor a[3],a[3]
int_num=0x23, ecx=0x4, eax=0x3   mov a[4],b[a[3]]
int_num=0x24, ecx=0x3, eax=0x2   mov b[a[3]],a[2]
int_num=0x27, ecx=0x2, eax=0x4   xor a[2],a[4]
int_num=0x24, ecx=0x0, eax=0x2   mov b[a[0]],a[2]
int_num=0x21, ecx=0x1, eax=0x1   mov a[1],1
int_num=0x25, ecx=0x0, eax=0x1   add a[0],a[1]
int_num=0x22, ecx=0x1, eax=0x0   mov a[1],a[0]
int_num=0x21, ecx=0x2, eax=0x81  mov a[2],0x81
int_num=0x26, ecx=0x1, eax=0x2   sub a[1],a[2]
int_num=0x21, ecx=0x2, eax=0x9   mov a[2],9
int_num=0x26, ecx=0x1, eax=0x2   sub a[1],a[2]
int_num=0x21, ecx=0x2, eax=0x9   mov a[2],9
int_num=0x2d, ecx=0x2, eax=0x1   test a[1],a[1]; jnz a[2]
int_num=0x21, ecx=0x0, eax=0x81  a[0]=0x81
int_num=0x22, ecx=0x1, eax=0x0   mov a[1],a[0]
int_num=0x21, ecx=0x2, eax=0x9   mov a[2],9
int_num=0x25, ecx=0x1, eax=0x2   add a[1],a[2]
int_num=0x23, ecx=0x3, eax=0x0   a[3]=b[a[0]]
int_num=0x23, ecx=0x4, eax=0x1   a[4]=b[a[1]]
int_num=0x26, ecx=0x3, eax=0x4   sub a[3],a[4]
int_num=0x21, ecx=0x4, eax=0x7e  mov a[4],0x7e
int_num=0x2d, ecx=0x4, eax=0x3   test a[3],a[3]; jnz a[4]
int_num=0x21, ecx=0x3, eax=0x1   mov a[3],1
int_num=0x25, ecx=0x0, eax=0x3   add a[0],a[3]
int_num=0x25, ecx=0x1, eax=0x3   add a[1],a[3]
int_num=0x26, ecx=0x2, eax=0x3   sub a[2],a[3]
int_num=0x21, ecx=0x4, eax=0x5a  mov a[4],0x5a
int_num=0x2d, ecx=0x4, eax=0x2   test a[2],a[2]; jnz a[4]
int_num=0x2f, ecx=0x0, eax=0x0
int_num=0x30, ecx=0x0, eax=0x0
```

��δ�����ڴ�0x0f4c���ļ�+114ch)����36���ֽڣ�����һϵ�����㣬�����ڴ�0x0f70���ļ�+1170h)��36���ֽڽ��бȽϣ���һ�������correct��������δ���󣬾Ϳ�����0x0f70����ֵ���Ƴ�flag�ˣ�

```
c = [0x65, 0x55, 0x63, 0x57, 0x1, 0x4, 0x53, 0x6, 0x49, 0x49, 0x49, 0x1f, 0x1f, 0x7, 0x57, 0x51, 0x57, 0x43, 0x5f, 0x57, 0x57, 0x5e, 0x43, 0x57, 0xa, 0x2, 0x57, 0x43, 0x5e, 0x3, 0x5e, 0x57, 0x0, 0x0, 0x59, 0xf]
tmp = [0, 0, 0, 0]

for i in range(0, len(c), 4):
	for j in range(4):
		tm2 = c[i+j]
		c[i+j] = c[i+j] ^ tmp[j]
		tmp[j] = c[i+j]
	c[i+1] = c[i+1] ^ c[i]
	c[i+2] = c[i+2] ^ c[i+1] ^ c[i]
	c[i+3] = c[i+3] ^ c[i+2] ^ c[i+1] ^ c[i]

flag1 = ''
for i in range(len(c)):
	flag1 += chr(c[i])

print(flag1)
```


flag{e064d5aa-5a72-11e9-9200-88e9fe80feaf}