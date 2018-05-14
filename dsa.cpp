#include<iostream>
#include<fstream>
#include<stdlib.h>
#include<openssl/sha.h>
#include<string.h>
#include<gmp.h>
#include<vector>
#include<cmath>
#include<time.h>
using namespace std;

gmp_randstate_t gmp_state;

//读取文件
//输入：文件名，buffer数组（用于存读取结果）
//输出：buffer数组长度
long readfile(char *filename,char *&buffer){
    long len;
    ifstream rf;
    rf.open(filename,ios::in|ios::binary|ios::ate);
    len=rf.tellg();
    rf.seekg(0,ios::beg);
    buffer=new char[len];
    rf.read(buffer,len);
    rf.close();    
    return len;
}

//对buffer数组进行哈希，并将结果转换成mpz_t类型（用于gmp的大整数运算）
//输入：buffer数组，数组长度，mpz_t变量
//无返回值
void hash(char *buffer,long len,mpz_t &M){
    unsigned char md[33] = {0};
    char result[96] = {0};
    char tmp[3]={0};
    SHA256((const unsigned char *)buffer,len, md);//openssl的sha256
    for(int i=0;i<32;i++){
        sprintf(tmp,"%d",md[i]);//字节数组转换成字符数组
        strcat(result,tmp);        
    }
    mpz_set_str(M,result,10);//mpz_t类型转换
}


//全局参数生成：p,q,g
void global_components(mpz_t &p,mpz_t &q,mpz_t &g){
    mpz_t tmp;
    mpz_t h;
    mpz_init(tmp);
    mpz_init(h);
    mpz_urandomb(q,gmp_state,160);//生成160bit的随机数
    mpz_nextprime(q,q);//生成素数q
    //反向求P，先求q，再将q*一个合数+1生成p
    do{
        mpz_urandomb(tmp,gmp_state,863);//生成863bit的随机数
        mpz_mul(p,tmp,q);
        mpz_add_ui(p,p,1);
        if(mpz_probab_prime_p(p,15)==1)break;
    }while(1);
    mpz_urandomm(h,gmp_state,p);//生成1到p-1的随机数
    mpz_sub_ui(tmp,p,1);//p-1
    mpz_cdiv_q(tmp,tmp,q);//(p-1)/q
    mpz_powm(g,h,tmp,p);//g = h^[(p-1)/q] % p    
}

//私钥x生成
void private_key(mpz_t q,mpz_t &x){
    mpz_urandomm(x,gmp_state,q);//生成1到q-1的随机数
}

//公钥y生成
void public_key(mpz_t g,mpz_t x,mpz_t p,mpz_t &y){
    mpz_powm(y,g,x,p);//y = g^x % p    
}

//秘密随机数k生成
void secret_number(mpz_t q,mpz_t &k){
    mpz_urandomm(k,gmp_state,q);//生成1到q-1的随机数 
}

//DSA签名
//输入：引用r,s;全局参数p,q,g;私钥x;秘密随机数k;文件哈希值HM;
bool dsa_sign(mpz_t &r,mpz_t &s,mpz_t p,mpz_t q,mpz_t g,mpz_t k,mpz_t x,mpz_t HM){
    mpz_t tmp;
    mpz_init(tmp);
    mpz_powm(r,g,k,p);//r = g^k % p
    mpz_mod(r,r,q);//r = r % q
    mpz_invert(tmp,k,q);//k^-1
    mpz_mul(s,x,r);//x*r
    mpz_add(s,s,HM);//HM+x*r
    mpz_mul(s,tmp,s);//k^-1(HM+x*r)
    mpz_mod(s,s,q);//[k^-1(HM+x*r)]%q
    return true;
}

//DSA验证
bool dsa_verify(mpz_t r,mpz_t s,mpz_t p,mpz_t q,mpz_t g,mpz_t y,mpz_t HM){
    mpz_t w,u1,u2,v,tmp;
    mpz_init(w);
    mpz_init(u1);
    mpz_init(u2);
    mpz_init(v);
    mpz_init(tmp);
    mpz_invert(w,s,q);//s^-1 % q
    mpz_mul(u1,HM,w);//HM*w
    mpz_mod(u1,u1,q);//[HM*w] mod q
    mpz_mul(u2,r,w);//r*w
    mpz_mod(u2,u2,q);//rw mod q
    mpz_powm(tmp,g,u1,p);//g^u1 mod p
    mpz_powm(v,y,u2,p);//y^u2 mod p
    mpz_mul(v,tmp,v);//g^u1*y^u2
    mpz_mod(v,v,p);//(g^u1*y^u2) mod p
    mpz_mod(v,v,q);//[(g^u1*y^u2) mod p] mod q
    gmp_printf("验证值v=%Zd\n",v);
    if(mpz_cmp(v,r)==0)return true;
    else return false;
}

int main(int argc, char * argv[])
{
    char *buffer;//buffer数组
    char *filename=argv[1];//命令行参数：文件名
    long len;//buffer数组长度
    mpz_t HM;
    mpz_t p,q,g;
    mpz_t x,y,k;
    mpz_t r,s;
    mpz_init(r);
    mpz_init(s);
    mpz_init(x);
    mpz_init(y);
    mpz_init(k);
    mpz_init(HM);
    mpz_init(p);
    mpz_init(q);
    mpz_init(g);
    gmp_randinit_mt(gmp_state);//用于随机数生成
    gmp_randseed_ui(gmp_state,(unsigned int)(time(NULL)));
    len=readfile(filename,buffer);//读取文件
    hash(buffer,len,HM);//对文件进行哈希
    global_components(p,q,g);//生成全局参数p,q,g
    cout<<"全局参数："<<endl;
    gmp_printf("p:%Zd\n",p);
    gmp_printf("q:%Zd\n",q);
    gmp_printf("g:%Zd\n",g); 
    private_key(q,x);//生成私钥x
    cout<<"私钥："<<endl;
    gmp_printf("x:%Zd\n",x);
    public_key(g,x,p,y);//生成公钥y
    cout<<"公钥："<<endl;
    gmp_printf("y:%Zd\n",y);
    secret_number(q,k);//生成秘密随机数k
    cout<<"秘密随机数："<<endl;
    gmp_printf("k:%Zd\n",k);
    dsa_sign(r,s,p,q,g,k,x,HM);//对明文M的哈希值进行签名
    cout<<"签名："<<endl;
    gmp_printf("(r:%Zd,\n%Zd)\n",r,s);
    cout<<"验证签名："<<endl;
    if(dsa_verify(r,s,p,q,g,y,HM))
    cout<<"验证成功！"<<endl;//对签名进行验证

    delete[] buffer;
    return 0;

}