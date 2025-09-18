# Basic_Crypto1 - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: crypto
- Difficulty (subjective): easy
- Points: 1
- Provided Files: encoded.txt
- tools:
## Brief Description
This Problem Basic_Crpyto(Roman emperor's cipher)  
FLAG FORMAT(A~Z) and empty is "_"  
DH{decode_Text}
## Initial Analysis
### encoded.txt
``` plain text
EDVLF FUBSWR GUHDPKDFN
```
## PoC(Poof of Concept)
카이사르 암호는 총 26개의 key개 존재하므로, 해당 키를 모두 전수 조사하면 FLAG를 복호화할 수 있다.  
### solve.py
``` python
encodedString = "EDVLF FUBSWR GUHDPKDFN"

decodedString = ""
for key in range(26) :
    for char in encodedString:
        if char.isalpha():
            shift = ord(char) - key
            if shift < ord('A'):
                shift += 26
            decodedString += chr(shift)
        else:
            decodedString += "_"
    print(f"Key {key}: {decodedString}")
    decodedString = "" 
```
### Result
``` sh
Key 0: EDVLF_FUBSWR_GUHDPKDFN
Key 1: DCUKE_ETARVQ_FTGCOJCEM
Key 2: CBTJD_DSZQUP_ESFBNIBDL
Key 3: BASIC_CRYPTO_DREAMHACK
Key 4: AZRHB_BQXOSN_CQDZLGZBJ
Key 5: ZYQGA_APWNRM_BPCYKFYAI
Key 6: YXPFZ_ZOVMQL_AOBXJEXZH
Key 7: XWOEY_YNULPK_ZNAWIDWYG
Key 8: WVNDX_XMTKOJ_YMZVHCVXF
Key 9: VUMCW_WLSJNI_XLYUGBUWE
Key 10: UTLBV_VKRIMH_WKXTFATVD
Key 11: TSKAU_UJQHLG_VJWSEZSUC
Key 12: SRJZT_TIPGKF_UIVRDYRTB
Key 13: RQIYS_SHOFJE_THUQCXQSA
Key 14: QPHXR_RGNEID_SGTPBWPRZ
Key 15: POGWQ_QFMDHC_RFSOAVOQY
Key 16: ONFVP_PELCGB_QERNZUNPX
Key 17: NMEUO_ODKBFA_PDQMYTMOW
Key 18: MLDTN_NCJAEZ_OCPLXSLNV
Key 19: LKCSM_MBIZDY_NBOKWRKMU
Key 20: KJBRL_LAHYCX_MANJVQJLT
Key 21: JIAQK_KZGXBW_LZMIUPIKS
Key 22: IHZPJ_JYFWAV_KYLHTOHJR
Key 23: HGYOI_IXEVZU_JXKGSNGIQ
Key 24: GFXNH_HWDUYT_IWJFRMFHP
Key 25: FEWMG_GVCTXS_HVIEQLEGO
```
총 26개의 key를 전수 조사한 결과다. 이 중에서 의미 있는 평문을 찾으면 된다.    