#include<stdio.h>
#include<string.h>
int main(){
    char t[100],s=3;
    printf("Enter the text: ");
    fgets(t, sizeof(t), stdin);
    for(int i=0;i<strlen(t);i++){
        if(t[i]>='A'&& t[i]<='Z'){
            t[i]=((t[i]-'A'+s)%26)+'A';
        }
        else if(t[i]>='a'&& t[i]<='z'){
            t[i]=((t[i]-'a'+s)%26)+'a';
        }
        else if(t[i]>='A'&& t[i]<='Z'){
            t[i]=((t[i]-'a'+s)%26)+'a';
        }
        else if(t[i]>='a'&& t[i]<='z'){
            t[i]=((t[i]-'a'+s)%26)+'a';
        }
    }
    printf("Encrypted text: %s",t);
    for(int i=0;i<strlen(t);i++){
        if(t[i]>='A'&& t[i]<='Z'){
            t[i]=((t[i]-'A'-s)%26)+'A';
        }
        else if(t[i]>='a'&& t[i]<='z'){
            t[i]=((t[i]-'a'-s)%26)+'a';
        }
        else if(t[i]>='A'&& t[i]<='Z'){
            t[i]=((t[i]-'a'-s)%26)+'a';
        }
        else if(t[i]>='a'&& t[i]<='z'){
            t[i]=((t[i]-'a'-s)%26)+'a';
        }
    }
    printf("Decrypted text: %s",t);
    return 0;
}