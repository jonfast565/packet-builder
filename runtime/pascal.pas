// ---- packet-builder runtime ---------------------------------------------

const
  /// The deepest packet nesting accepted.
  PbMaxDepth = 64;

type
  /// What went wrong while decoding or encoding.
  TPbErrorKind = (
    pekIncomplete, // the input ended before the packet did; NeededBits more would help
    pekInvalid,    // malformed data: a bad length, nesting too deep, ...
    pekRange,      // a value does not fit in its field
    pekText,       // a string is not valid text, or contains a NUL where none is allowed
    pekMismatch,   // a length, derived field or checksum does not match the data
    pekConstraint  // a value breaks a declared constraint
  );

  /// Raised when data cannot be decoded or a value cannot be encoded.
  EPbError = class(Exception)
  public
    Kind: TPbErrorKind;
    /// Where it happened: Packet.field[index].field.
    Path: string;
    BitOffset: Int64;
    /// For pekIncomplete: the least number of extra input bits needed.
    NeededBits: Int64;
    Reason: string;
    constructor CreatePb(AKind: TPbErrorKind; const AReason, APath: string; ABitOffset: Int64;
      ANeededBits: Int64 = 0);
  end;

  TPbFrame = record
    Packet: string;
    Field: string;
    Index: Int64;
  end;

  // @versions{
  /// A version scope left for another, and its version.
  TPbScope = record
    Scope, Version: Integer;
  end;

  // @versions}
  /// The packets being decoded or encoded, innermost last, each with the
  /// field it is working on: the path reported in errors.
  TPbTrace = class
  protected
    FFrames: array of TPbFrame;
    FDepth: Integer;
    FPos: Int64; // in bits
    FVersion: Integer; // protocol version; 0 until set
    /// Start from the frames (and version) of Other (for sub writers).
    procedure CopyFrames(Other: TPbTrace);
  public
    procedure Enter(const APacket: string);
    procedure Leave;
    procedure At(const AField: string);
    procedure AtIndex(AIndex: Int64);
    function Path: string;
    function Error(AKind: TPbErrorKind; const AReason: string; ANeededBits: Int64 = 0): EPbError;
    property PositionBits: Int64 read FPos;
    // @versions{
    /// The protocol version (`version`), or ALatest while none is set.
    function VersionOr(ALatest: Integer): Int64;
    /// Code as protocol version V, which must be in AMin..ALatest.
    procedure SetVersion(V: Int64; AMin, ALatest: Integer);
    /// The version a value carries in-band: used unless one is set already.
    procedure AdoptVersion(V: Int64; AMin, ALatest: Integer);
    /// Code a packet of version scope S (`version_scope`): whether a scope
    /// was entered (for LeaveScope). A scope entered from another starts
    /// without a version, unless it was left for it earlier.
    function EnterScope(S: Integer): Boolean;
    /// After that packet: back to the outer scope and its version.
    procedure LeaveScope(Entered: Boolean);
  protected
    FScope: Integer; // version scope being coded, plus 1 (0 before any)
    FScopes: array of TPbScope; // the scopes left for it, and their versions
    FScopeDepth: Integer;
    // @versions}
  end;

  /// Where a reader was before Jump.
  TPbJump = record
    Pos, Limit: Int64;
    Windows: Integer;
  end;

  /// Fills Buf with the input bytes at AOffset; raises an exception (whose
  /// message is reported) when it cannot.
  TPbFetch = procedure(AOffset: Int64; var Buf: array of Byte) of object;

  /// Input read on demand (a file, a stream that can seek): Size bytes,
  /// loaded a page at a time by a TPbFetch. Only the pages a decode touches
  /// are fetched: fields a view skips are never read. Pages stay loaded
  /// while the source lives; free its readers first.
  TPbSource = class
  private
    FBuf: TBytes; // the whole input, zero until loaded
    FPage: Int64;
    FLoaded: array of Boolean; // per page
    FFetch: TPbFetch;
    FFile: THandle;
    FOwnsFile: Boolean;
    procedure FetchFile(AOffset: Int64; var Buf: array of Byte);
  public
    /// A source of ALen bytes read in pages of APage bytes.
    constructor Create(ALen, APage: Int64; AFetch: TPbFetch);
    /// A source reading the file AFileName (pages of 4096 bytes).
    constructor CreateFile(const AFileName: string);
    destructor Destroy; override;
    function Size: Int64;
    /// Fetch the pages holding bytes AStart..AStart + N - 1 that are not
    /// loaded yet; false (with the fetch's message in Why) when one fails.
    function Load(AStart, N: Int64; out Why: string): Boolean;
  end;

  /// Reads integers of any bit width (MSB-first) and byte-aligned values.
  TPbReader = class(TPbTrace)
  private
    FData: TBytes;
    FSource: TPbSource; // nil for a buffer
    FLimit: Int64; // end of the readable data in bits (a window inside the data)
    FWindows: Integer; // windows open
    function Short(Bits: Int64; const What: string): EPbError;
    procedure Need(Bits: Int64);
    procedure Load(AStart, N: Int64);
    function Find(AStart, AStop: Int64; const Term: array of Byte): Int64;
  public
    constructor Create(const AData: TBytes);
    /// A reader that fetches its input from ASource as it goes (the source
    /// must outlive it).
    constructor CreateFromSource(ASource: TPbSource);
    function RemainingBits: Int64;
    /// Whole bytes left before the end of the window or input (`remaining`).
    function RemainingBytes: Int64;
    /// Read from AOffset bytes after bit AFrom (the packet start, or 0 for
    /// the start of the input) until JumpBack; windows do not apply there.
    function Jump(AFrom, AOffset: Int64): TPbJump;
    /// Return to where Jump left.
    procedure JumpBack(const Saved: TPbJump);
    /// Restrict reading to the next N bytes; returns the previous limit.
    function PushLimit(N: Int64): Int64;
    /// Skip what is left of the current window and restore Saved; with
    /// Exact, bytes left over are an error.
    procedure PopLimit(Saved: Int64; Exact: Boolean);
    function ReadBits(Width: Integer): UInt64;
    function ReadUint(NBytes: Integer; Little: Boolean): UInt64;
    function ReadBytes(N: Int64): TBytes;
    procedure SkipBits(Bits: Int64);
    /// Bytes before a NUL terminator; the terminator is consumed.
    function ReadCString: TBytes;
    /// Validate a decoded element count against the data that is left.
    function Count(N, ElemBits: Int64): Integer;
    function DecodeUtf8(const Raw: TBytes; UntilNul: Boolean): string;
    /// Text in encoding Enc (0 UTF-8, 1 ASCII, 2 Latin-1, 3 UTF-16LE,
    /// 4 UTF-16BE); Padded cuts it at the first NUL character.
    function DecodeText(const Raw: TBytes; Enc: Integer; Padded: Boolean): string;
    /// One variable-length integer (kind: 0 uleb128, 1 sleb128, 2 zigzag,
    /// 3 vlq, 4 quic, 5 varint15); signed kinds return the two's complement bits.
    function ReadVarint(Kind: Integer): UInt64;
    /// The bytes before Term, consuming both. Without the terminator: the
    /// rest of the input when Optional, otherwise an error.
    function ReadUntil(const Term: array of Byte; Optional: Boolean): TBytes;
    /// Checksum Algo of the input between two bit positions (whole bytes);
    /// the bytes between HoleFrom and HoleTo count as zero. From a source
    /// that cannot be read, the checksum of zeros (which then fails to match).
    function Checksum(Algo: Integer; AFrom, ATo, HoleFrom, HoleTo: Int64): UInt64;
  end;

  TPbPlaced = record
    At: Int64;
    Data: TBytes;
    Path: string;
  end;

  /// Builds a byte buffer; integers may be written at any bit position.
  TPbWriter = class(TPbTrace)
  private
    FBuf: TBytes;
    FLen: Integer;
    FBase: Int64; // where the buffer goes in the output (sub writers)
    FPlaced: array of TPbPlaced;
    procedure AddByte(B: Byte);
  public
    function ToBytes: TBytes;
    /// A writer for a packet placed AOffset bytes after bit AFrom of this
    /// writer (the packet start), or after the start of the output (Root).
    function Sub(AFrom, AOffset: Int64; Root: Boolean): TPbWriter;
    /// Keep what S wrote, for Finish.
    procedure Place(S: TPbWriter);
    /// The output, with every placed packet written at its offset: past the
    /// end (zero-filling the gap), or over bytes that must already match.
    function Finish: TBytes;
    procedure WriteBits(Value: UInt64; Width: Integer);
    procedure WriteUint(Value: UInt64; NBytes: Integer; Little: Boolean);
    procedure WriteBytes(const Bytes: array of Byte);
    procedure WriteZeroBits(Bits: Int64);
    /// End a window of Size bytes that started at bit Start: the content
    /// must fit (and fill it when Exact); the rest is zero-filled.
    procedure EndWindow(Start, Size: Int64; Exact: Boolean);
    /// Overwrite NBytes bytes at bit position AAt (byte aligned).
    procedure PatchUint(AAt: Int64; Value: UInt64; NBytes: Integer; Little: Boolean);
    /// Overwrite Width bits at bit position AAt, MSB first.
    procedure PatchBits(AAt: Int64; Value: UInt64; Width: Integer);
    /// Checksum Algo of the output between two bit positions (whole bytes);
    /// the bytes between HoleFrom and HoleTo count as zero.
    function Checksum(Algo: Integer; AFrom, ATo, HoleFrom, HoleTo: Int64): UInt64;
    function Utf8Bytes(const S: string): TBytes;
    /// S in encoding Enc (see TPbReader.DecodeText).
    function TextBytes(const S: string; Enc: Integer): TBytes;
    /// One variable-length integer (see TPbReader.ReadVarint).
    procedure WriteVarint(Kind: Integer; V: UInt64);
    procedure CheckNoTerm(const Data, Term: array of Byte);
    procedure CheckFits(Length, Size: Int64);
    procedure CheckNoNul(const Data: TBytes);
    procedure CheckLen(Actual, Expected: Int64);
    procedure CheckU(V: UInt64; Width: Integer);
    procedure CheckI(V: Int64; Width: Integer);
  end;

  TPbInt8Array = array of Int8;
  TPbInt16Array = array of Int16;
  TPbUInt16Array = array of UInt16;
  TPbInt32Array = array of Int32;
  TPbUInt32Array = array of UInt32;
  TPbInt64Array = array of Int64;
  TPbUInt64Array = array of UInt64;
  TPbSingleArray = array of Single;
  TPbDoubleArray = array of Double;
  TPbStringArray = array of string;
  TPbBytesArray = array of TBytes;

/// The name of an error kind (`incomplete`, `invalid`, ...).
function PbKindName(Kind: TPbErrorKind): string;
/// Padding needed after Offset bits to reach a multiple of Units bits.
function PbPad(Offset, Units: Int64): Int64;
function PbSext(V: UInt64; Width: Integer): Int64;
function PbTrunc(V: Int64; Width: Integer; Signed: Boolean): Int64;
function PbDiv(A, B: Int64): Int64;
function PbMod(A, B: Int64): Int64;
function PbShl(A, B: Int64): Int64;
function PbShr(A, B: Int64): Int64;
function PbPow(B, E: Int64): Int64;
function PbPowF(B, E: Double): Double;
function PbFtoI(V: Double): Int64;
function PbItoF(V: Int64): Double;
function PbIfI(C: Boolean; A, B: Int64): Int64;
function PbIfF(C: Boolean; A, B: Double): Double;
function PbIfB(C: Boolean; A, B: Boolean): Boolean;
function PbMinI(A, B: Int64): Int64;
function PbMaxI(A, B: Int64): Int64;
function PbMinF(A, B: Double): Double;
function PbMaxF(A, B: Double): Double;
function PbSqrt(V: Double): Double;
/// The bytes S takes in UTF-8.
function PbUtf8Len(const S: string): Int64;
/// Element I of an array; 0 when I is out of range.
function PbAt(const A: TBytes; I: Int64): Int64; overload;
function PbAt(const A: TPbInt8Array; I: Int64): Int64; overload;
function PbAt(const A: TPbInt16Array; I: Int64): Int64; overload;
function PbAt(const A: TPbUInt16Array; I: Int64): Int64; overload;
function PbAt(const A: TPbInt32Array; I: Int64): Int64; overload;
function PbAt(const A: TPbUInt32Array; I: Int64): Int64; overload;
function PbAt(const A: TPbInt64Array; I: Int64): Int64; overload;
function PbAt(const A: TPbUInt64Array; I: Int64): Int64; overload;
function PbAt(const A: TPbSingleArray; I: Int64): Double; overload;
function PbAt(const A: TPbDoubleArray; I: Int64): Double; overload;
/// The sum (wrapping) and product of an array's elements.
function PbSum(const A: TBytes): Int64; overload;
function PbSum(const A: TPbInt8Array): Int64; overload;
function PbSum(const A: TPbInt16Array): Int64; overload;
function PbSum(const A: TPbUInt16Array): Int64; overload;
function PbSum(const A: TPbInt32Array): Int64; overload;
function PbSum(const A: TPbUInt32Array): Int64; overload;
function PbSum(const A: TPbInt64Array): Int64; overload;
function PbSum(const A: TPbUInt64Array): Int64; overload;
function PbSum(const A: TPbSingleArray): Double; overload;
function PbSum(const A: TPbDoubleArray): Double; overload;
function PbProduct(const A: TBytes): Int64; overload;
function PbProduct(const A: TPbInt8Array): Int64; overload;
function PbProduct(const A: TPbInt16Array): Int64; overload;
function PbProduct(const A: TPbUInt16Array): Int64; overload;
function PbProduct(const A: TPbInt32Array): Int64; overload;
function PbProduct(const A: TPbUInt32Array): Int64; overload;
function PbProduct(const A: TPbInt64Array): Int64; overload;
function PbProduct(const A: TPbUInt64Array): Int64; overload;
function PbProduct(const A: TPbSingleArray): Double; overload;
function PbProduct(const A: TPbDoubleArray): Double; overload;
/// Bytes as a JSON string of hex digits (for ToJson).
function PbJsonHex(const B: TBytes): string;
/// A JSON string literal, ASCII only (for ToJson).
function PbJsonStr(const S: string): string;
function PbJsonI(V: Int64): string;
function PbJsonU(V: UInt64): string;
function PbJsonF(V: Double): string;
/// Checksum Algo of Buf[AFrom..ATo) with Buf[HoleFrom..HoleTo) as zeros
/// (algorithm numbers as in the other runtimes).
function PbChecksum(Algo: Integer; const Buf: TBytes; AFrom, ATo, HoleFrom, HoleTo: Int64): UInt64;
/// N zero bytes.
function PbZeros(N: Integer): TBytes;
/// IEEE 754 bit patterns of floats, and back.
function PbBitsToSingle(V: UInt64): Single;
function PbBitsToDouble(V: UInt64): Double;
function PbSingleToBits(V: Single): UInt64;
function PbDoubleToBits(V: Double): UInt64;

// ---- generated declarations ---------------------------------------------
// @implementation

// ---- packet-builder runtime ---------------------------------------------

{ EPbError }

constructor EPbError.CreatePb(AKind: TPbErrorKind; const AReason, APath: string; ABitOffset: Int64;
  ANeededBits: Int64);
var
  Msg: string;
begin
  Msg := AReason + ' (at bit ' + IntToStr(ABitOffset) + ')';
  if APath <> '' then
    Msg := APath + ': ' + Msg;
  inherited Create(Msg);
  Kind := AKind;
  Reason := AReason;
  Path := APath;
  BitOffset := ABitOffset;
  NeededBits := ANeededBits;
end;

{ TPbTrace }

procedure TPbTrace.Enter(const APacket: string);
begin
  if FDepth >= Length(FFrames) then
    SetLength(FFrames, FDepth * 2 + 4);
  FFrames[FDepth].Packet := APacket;
  FFrames[FDepth].Field := '';
  FFrames[FDepth].Index := -1;
  Inc(FDepth);
  if FDepth > PbMaxDepth then
    raise Error(pekInvalid, 'packets nested more than ' + IntToStr(PbMaxDepth) + ' deep');
end;

procedure TPbTrace.Leave;
begin
  Dec(FDepth);
end;

procedure TPbTrace.CopyFrames(Other: TPbTrace);
var
  I: Integer;
begin
  for I := 0 to Other.FDepth - 1 do
  begin
    Enter(Other.FFrames[I].Packet);
    FFrames[I] := Other.FFrames[I];
  end;
  FVersion := Other.FVersion;
  // @versions{
  FScope := Other.FScope;
  FScopes := Copy(Other.FScopes, 0, Other.FScopeDepth);
  FScopeDepth := Other.FScopeDepth;
  // @versions}
end;

// @versions{
function TPbTrace.VersionOr(ALatest: Integer): Int64;
begin
  if FVersion = 0 then
    Result := ALatest
  else
    Result := FVersion;
end;

procedure TPbTrace.SetVersion(V: Int64; AMin, ALatest: Integer);
begin
  if (V < AMin) or (V > ALatest) then
    raise Error(pekConstraint, 'version ' + IntToStr(V) + ' is not one of the versions ' + IntToStr(AMin) + '..' +
      IntToStr(ALatest));
  FVersion := V;
end;

procedure TPbTrace.AdoptVersion(V: Int64; AMin, ALatest: Integer);
begin
  if FVersion = 0 then
    SetVersion(V, AMin, ALatest);
end;

function TPbTrace.EnterScope(S: Integer): Boolean;
var
  I, V: Integer;
begin
  Inc(S);
  Result := FScope <> S;
  if not Result then
    Exit;
  if FScope = 0 then
    V := FVersion
  else
  begin
    V := 0;
    for I := FScopeDepth - 1 downto 0 do
      if FScopes[I].Scope = S then
      begin
        V := FScopes[I].Version;
        Break;
      end;
  end;
  if FScopeDepth >= Length(FScopes) then
    SetLength(FScopes, FScopeDepth * 2 + 4);
  FScopes[FScopeDepth].Scope := FScope;
  FScopes[FScopeDepth].Version := FVersion;
  Inc(FScopeDepth);
  FScope := S;
  FVersion := V;
end;

procedure TPbTrace.LeaveScope(Entered: Boolean);
begin
  if not Entered then
    Exit;
  if FScopeDepth = 0 then
  begin
    FScope := 0;
    Exit;
  end;
  Dec(FScopeDepth);
  FScope := FScopes[FScopeDepth].Scope;
  FVersion := FScopes[FScopeDepth].Version;
end;
// @versions}

procedure TPbTrace.At(const AField: string);
begin
  FFrames[FDepth - 1].Field := AField;
  FFrames[FDepth - 1].Index := -1;
end;

procedure TPbTrace.AtIndex(AIndex: Int64);
begin
  FFrames[FDepth - 1].Index := AIndex;
end;

function TPbTrace.Path: string;
var
  I: Integer;
begin
  Result := '';
  if FDepth > 0 then
    Result := FFrames[0].Packet;
  for I := 0 to FDepth - 1 do
  begin
    if FFrames[I].Field = '' then
      Break;
    Result := Result + '.' + FFrames[I].Field;
    if FFrames[I].Index >= 0 then
      Result := Result + '[' + IntToStr(FFrames[I].Index) + ']';
  end;
end;

function TPbTrace.Error(AKind: TPbErrorKind; const AReason: string; ANeededBits: Int64): EPbError;
begin
  Result := EPbError.CreatePb(AKind, AReason, Path, FPos, ANeededBits);
end;

{ TPbSource }

constructor TPbSource.Create(ALen, APage: Int64; AFetch: TPbFetch);
begin
  inherited Create;
  if APage < 1 then
    APage := 1;
  SetLength(FBuf, ALen);
  if ALen > 0 then
    FillChar(FBuf[0], ALen, 0);
  FPage := APage;
  SetLength(FLoaded, (ALen + APage - 1) div APage);
  if Length(FLoaded) > 0 then
    FillChar(FLoaded[0], Length(FLoaded) * SizeOf(Boolean), 0);
  FFetch := AFetch;
end;

constructor TPbSource.CreateFile(const AFileName: string);
var
  H: THandle;
  Len: Int64;
begin
  H := FileOpen(AFileName, fmOpenRead or fmShareDenyWrite);
  if H = THandle(-1) then
    raise Exception.Create('cannot open ' + AFileName);
  Len := FileSeek(H, Int64(0), 2);
  if Len < 0 then
  begin
    FileClose(H);
    raise Exception.Create('cannot seek in ' + AFileName);
  end;
  Create(Len, 4096, FetchFile);
  FFile := H;
  FOwnsFile := True;
end;

destructor TPbSource.Destroy;
begin
  if FOwnsFile then
    FileClose(FFile);
  inherited Destroy;
end;

procedure TPbSource.FetchFile(AOffset: Int64; var Buf: array of Byte);
begin
  if FileSeek(FFile, AOffset, 0) <> AOffset then
    raise Exception.Create('cannot seek to ' + IntToStr(AOffset));
  if (Length(Buf) > 0) and (FileRead(FFile, Buf[0], Length(Buf)) <> Length(Buf)) then
    raise Exception.Create('short read at ' + IntToStr(AOffset));
end;

function TPbSource.Size: Int64;
begin
  Result := Length(FBuf);
end;

function TPbSource.Load(AStart, N: Int64; out Why: string): Boolean;
var
  P, From, Len: Int64;
  Tmp: TBytes;
  Failed: Boolean;
begin
  Why := '';
  Result := True;
  if N <= 0 then
    Exit;
  for P := AStart div FPage to (AStart + N - 1) div FPage do
  begin
    if FLoaded[P] then
      Continue;
    From := P * FPage;
    Len := Length(FBuf) - From;
    if Len > FPage then
      Len := FPage;
    SetLength(Tmp, Len);
    Failed := False;
    try
      FFetch(From, Tmp);
    except
      on E: Exception do
      begin
        Why := E.Message;
        Failed := True;
      end;
    end;
    if Failed then
    begin
      Result := False;
      Exit;
    end;
    Move(Tmp[0], FBuf[From], Len);
    FLoaded[P] := True;
  end;
end;

{ TPbReader }

constructor TPbReader.Create(const AData: TBytes);
begin
  inherited Create;
  FData := AData;
  FLimit := Int64(Length(AData)) * 8;
end;

constructor TPbReader.CreateFromSource(ASource: TPbSource);
begin
  inherited Create;
  // The same array: pages the source loads appear in FData.
  FData := ASource.FBuf;
  FSource := ASource;
  FLimit := Int64(Length(FData)) * 8;
end;

// Make input bytes AStart..AStart + N - 1 (which exist) readable.
procedure TPbReader.Load(AStart, N: Int64);
var
  Why: string;
begin
  if (FSource <> nil) and not FSource.Load(AStart, N, Why) then
    raise Error(pekInvalid, 'cannot read the input: ' + Why);
end;

// Where Term first starts in input bytes AStart..AStop - 1, or -1.
function TPbReader.Find(AStart, AStop: Int64; const Term: array of Byte): Int64;
var
  From, ATo, I: Int64;
  K: Integer;
  Hit: Boolean;
begin
  Result := -1;
  From := AStart;
  while From < AStop do
  begin
    ATo := AStop;
    if FSource <> nil then
    begin
      // Page by page, so a long input is only read up to the terminator.
      ATo := (From div FSource.FPage + 1) * FSource.FPage + Length(Term) - 1;
      if ATo > AStop then
        ATo := AStop;
      Load(From, ATo - From);
    end;
    I := From;
    while I + Length(Term) <= ATo do
    begin
      Hit := True;
      for K := 0 to High(Term) do
        if FData[I + K] <> Term[K] then
        begin
          Hit := False;
          Break;
        end;
      if Hit then
      begin
        Result := I;
        Exit;
      end;
      Inc(I);
    end;
    if ATo = AStop then
      Break;
    From := ATo + 1 - Length(Term);
  end;
end;

function TPbReader.RemainingBits: Int64;
begin
  Result := FLimit - FPos;
end;

function TPbReader.RemainingBytes: Int64;
begin
  Result := (FLimit - FPos) div 8;
end;

function TPbReader.Jump(AFrom, AOffset: Int64): TPbJump;
begin
  if (AOffset < 0) or (AFrom mod 8 <> 0) or (AOffset > Length(FData)) or
    (AFrom + AOffset * 8 > Int64(Length(FData)) * 8) then
    raise Error(pekInvalid, 'offset ' + IntToStr(AOffset) + ' is past the end of the input');
  Result.Pos := FPos;
  Result.Limit := FLimit;
  Result.Windows := FWindows;
  FPos := AFrom + AOffset * 8;
  FLimit := Int64(Length(FData)) * 8;
  FWindows := 0;
end;

procedure TPbReader.JumpBack(const Saved: TPbJump);
begin
  FPos := Saved.Pos;
  FLimit := Saved.Limit;
  FWindows := Saved.Windows;
end;

function TPbReader.Short(Bits: Int64; const What: string): EPbError;
begin
  if FWindows = 0 then
    Result := Error(pekIncomplete, 'unexpected end of data: ' + What + ' needs ' + IntToStr(Bits) +
      ' more bit(s), ' + IntToStr(RemainingBits) + ' left', Bits - RemainingBits)
  else
    Result := Error(pekInvalid, What + ' needs ' + IntToStr(Bits) + ' bit(s) but its window has ' +
      IntToStr(RemainingBits) + ' left');
end;

procedure TPbReader.Need(Bits: Int64);
begin
  if (Bits < 0) or (Bits > RemainingBits) then
    raise Short(Bits, 'the field');
end;

function TPbReader.PushLimit(N: Int64): Int64;
begin
  if N < 0 then
    raise Error(pekInvalid, 'negative size ' + IntToStr(N));
  if N > RemainingBits div 8 then
    raise Short(N * 8, 'the window');
  Result := FLimit;
  FLimit := FPos + N * 8;
  Inc(FWindows);
end;

procedure TPbReader.PopLimit(Saved: Int64; Exact: Boolean);
begin
  if Exact and (RemainingBits > 0) then
    raise Error(pekInvalid, IntToStr(RemainingBits) + ' bit(s) left over in a field that must fill its size');
  FPos := FLimit;
  FLimit := Saved;
  Dec(FWindows);
end;

function TPbReader.ReadBits(Width: Integer): UInt64;
var
  Left, Off, Take, B: Integer;
begin
  Need(Width);
  Load(FPos shr 3, (FPos + Width + 7) shr 3 - FPos shr 3);
  Result := 0;
  Left := Width;
  while Left > 0 do
  begin
    B := FData[FPos shr 3];
    Off := FPos and 7;
    Take := 8 - Off;
    if Take > Left then
      Take := Left;
    Result := (Result shl Take) or UInt64((B shr (8 - Off - Take)) and ((1 shl Take) - 1));
    Inc(FPos, Take);
    Dec(Left, Take);
  end;
end;

function TPbReader.ReadUint(NBytes: Integer; Little: Boolean): UInt64;
var
  Start: Int64;
  I: Integer;
begin
  Need(Int64(NBytes) * 8);
  Start := FPos shr 3;
  Load(Start, NBytes);
  Result := 0;
  for I := 0 to NBytes - 1 do
    if Little then
      Result := (Result shl 8) or FData[Start + NBytes - 1 - I]
    else
      Result := (Result shl 8) or FData[Start + I];
  Inc(FPos, Int64(NBytes) * 8);
end;

function TPbReader.ReadBytes(N: Int64): TBytes;
begin
  Need(N * 8);
  Load(FPos shr 3, N);
  SetLength(Result, N);
  if N > 0 then
    Move(FData[FPos shr 3], Result[0], N);
  Inc(FPos, N * 8);
end;

procedure TPbReader.SkipBits(Bits: Int64);
begin
  Need(Bits);
  Inc(FPos, Bits);
end;

function TPbReader.ReadCString: TBytes;
var
  Start, I: Int64;
begin
  Start := FPos shr 3;
  I := Find(Start, FLimit shr 3, [0]);
  if I < 0 then
    raise Short(RemainingBits + 8, 'the NUL-terminated string');
  Load(Start, I - Start);
  SetLength(Result, I - Start);
  if I > Start then
    Move(FData[Start], Result[0], I - Start);
  FPos := (I + 1) * 8;
end;

function TPbReader.Count(N, ElemBits: Int64): Integer;
var
  Bits: Int64;
begin
  if N < 0 then
    raise Error(pekInvalid, 'negative length ' + IntToStr(N));
  if (ElemBits > 0) and (N > RemainingBits div ElemBits) then
  begin
    if N > High(Int64) div ElemBits then
      Bits := High(Int64)
    else
      Bits := N * ElemBits;
    raise Short(Bits, 'length ' + IntToStr(N));
  end;
  Result := N;
end;

/// Strict UTF-8 (no overlong forms, surrogates or values past U+10FFFF).
function PbFromUtf8(const Raw: TBytes; N: Integer; out S: string): Boolean;
var
  I, K, More, Len: Integer;
  C, Lo: Cardinal;
begin
  Result := False;
  SetLength(S, N);
  Len := 0;
  I := 0;
  while I < N do
  begin
    C := Raw[I];
    if C < $80 then
      More := 0
    else if (C >= $C2) and (C <= $DF) then
    begin
      More := 1;
      C := C and $1F;
    end
    else if (C >= $E0) and (C <= $EF) then
    begin
      More := 2;
      C := C and $0F;
    end
    else if (C >= $F0) and (C <= $F4) then
    begin
      More := 3;
      C := C and $07;
    end
    else
      Exit;
    for K := 1 to More do
    begin
      if (I + K >= N) or (Raw[I + K] and $C0 <> $80) then
        Exit;
      C := (C shl 6) or (Raw[I + K] and $3F);
    end;
    if ((More = 2) and ((C < $800) or ((C >= $D800) and (C <= $DFFF)))) or
      ((More = 3) and ((C < $10000) or (C > $10FFFF))) then
      Exit;
    Inc(I, More + 1);
    if C >= $10000 then
    begin
      Lo := C - $10000;
      S[Len + 1] := Char($D800 + (Lo shr 10));
      S[Len + 2] := Char($DC00 + (Lo and $3FF));
      Inc(Len, 2);
    end
    else
    begin
      S[Len + 1] := Char(C);
      Inc(Len);
    end;
  end;
  SetLength(S, Len);
  Result := True;
end;

function TPbReader.DecodeUtf8(const Raw: TBytes; UntilNul: Boolean): string;
var
  N, I: Integer;
begin
  N := Length(Raw);
  if UntilNul then
    for I := 0 to Length(Raw) - 1 do
      if Raw[I] = 0 then
      begin
        N := I;
        Break;
      end;
  if not PbFromUtf8(Raw, N, Result) then
    raise Error(pekText, 'invalid UTF-8');
end;

function TPbReader.DecodeText(const Raw: TBytes; Enc: Integer; Padded: Boolean): string;
var
  N, I, Units: Integer;
  C, D: Cardinal;
begin
  if Enc = 0 then
    Exit(DecodeUtf8(Raw, Padded));
  N := Length(Raw);
  if Enc >= 3 then
    Units := 2
  else
    Units := 1;
  if N mod Units <> 0 then
    raise Error(pekText, 'invalid UTF-16 (an odd number of bytes)');
  if Padded then
  begin
    I := 0;
    while I < N do
    begin
      if (Raw[I] = 0) and (Raw[I + Units - 1] = 0) then
      begin
        N := I;
        Break;
      end;
      Inc(I, Units);
    end;
  end;
  SetLength(Result, N div Units);
  for I := 0 to N div Units - 1 do
  begin
    case Enc of
      3: C := Raw[2 * I] or (Cardinal(Raw[2 * I + 1]) shl 8);
      4: C := (Cardinal(Raw[2 * I]) shl 8) or Raw[2 * I + 1];
    else
      C := Raw[I];
    end;
    if (Enc = 1) and (C > $7F) then
      raise Error(pekText, 'invalid ASCII');
    Result[I + 1] := Char(C);
  end;
  if Enc >= 3 then
  begin
    // Surrogates come in pairs: a high one, then a low one.
    I := 1;
    while I <= Length(Result) do
    begin
      C := Ord(Result[I]);
      if (C >= $D800) and (C <= $DBFF) then
      begin
        if I = Length(Result) then
          raise Error(pekText, 'invalid UTF-16');
        D := Ord(Result[I + 1]);
        if (D < $DC00) or (D > $DFFF) then
          raise Error(pekText, 'invalid UTF-16');
        Inc(I);
      end
      else if (C >= $DC00) and (C <= $DFFF) then
        raise Error(pekText, 'invalid UTF-16');
      Inc(I);
    end;
  end;
end;

function TPbReader.ReadVarint(Kind: Integer): UInt64;
var
  First, B, Q: UInt64;
  N, Shift: Integer;
  LastOk: Boolean;
begin
  if Kind = 5 then
  begin
    First := ReadUint(1, False);
    if First and $80 = 0 then
      Exit(First);
    Exit(((First and $7F) shl 8) or ReadUint(1, False));
  end;
  if Kind = 4 then
  begin
    First := ReadUint(1, False);
    N := 1 shl Integer(First shr 6);
    Q := First and $3F;
    if N > 1 then
      Q := (Q shl (8 * (N - 1))) or ReadUint(N - 1, False);
    Exit(Q);
  end;
  Result := 0;
  Shift := 0;
  while True do
  begin
    B := ReadUint(1, False);
    if Kind = 3 then
    begin
      if Result shr 57 <> 0 then
        raise Error(pekInvalid, 'the varint does not fit in 64 bits');
      Result := (Result shl 7) or (B and $7F);
    end
    else
    begin
      // The 10th byte holds bit 63 only (and, for sleb128, its sign).
      if Kind = 1 then
        LastOk := (B and $7F = 0) or (B and $7F = $7F)
      else
        LastOk := B and $7E = 0;
      if (Shift >= 64) or ((Shift = 63) and ((B and $80 <> 0) or not LastOk)) then
        raise Error(pekInvalid, 'the varint does not fit in 64 bits');
      Result := Result or ((B and $7F) shl Shift);
    end;
    Inc(Shift, 7);
    if B and $80 = 0 then
    begin
      if (Kind = 1) and (Shift < 64) and (B and $40 <> 0) then
        Result := Result or (High(UInt64) shl Shift);
      Break;
    end;
  end;
  if Kind = 2 then
    Result := (Result shr 1) xor (UInt64(0) - (Result and 1));
end;

function TPbReader.ReadUntil(const Term: array of Byte; Optional: Boolean): TBytes;
var
  Start, Stop, I: Int64;
begin
  Start := FPos shr 3;
  Stop := FLimit shr 3;
  I := Find(Start, Stop, Term);
  if I >= 0 then
  begin
    Load(Start, I - Start);
    SetLength(Result, I - Start);
    if I > Start then
      Move(FData[Start], Result[0], I - Start);
    FPos := (I + Length(Term)) * 8;
    Exit;
  end;
  if not Optional then
    raise Short(RemainingBits + 8, 'the terminated field');
  Load(Start, Stop - Start);
  SetLength(Result, Stop - Start);
  if Stop > Start then
    Move(FData[Start], Result[0], Stop - Start);
  FPos := FLimit;
end;

function TPbReader.Checksum(Algo: Integer; AFrom, ATo, HoleFrom, HoleTo: Int64): UInt64;
var
  Base, N: Int64;
  Why: string;
begin
  Base := AFrom div 8;
  N := ATo div 8 - Base;
  if (FSource = nil) or FSource.Load(Base, N, Why) then
  begin
    Result := PbChecksum(Algo, FData, Base, ATo div 8, HoleFrom div 8, HoleTo div 8);
    Exit;
  end;
  if N < 0 then
    N := 0;
  Result := PbChecksum(Algo, PbZeros(N), 0, N, Max(HoleFrom div 8 - Base, Int64(0)), Max(HoleTo div 8 - Base, Int64(0)));
end;

{ TPbWriter }

procedure TPbWriter.AddByte(B: Byte);
begin
  if FLen >= Length(FBuf) then
    SetLength(FBuf, FLen * 2 + 16);
  FBuf[FLen] := B;
  Inc(FLen);
end;

function TPbWriter.ToBytes: TBytes;
begin
  Result := Copy(FBuf, 0, FLen);
end;

function TPbWriter.Sub(AFrom, AOffset: Int64; Root: Boolean): TPbWriter;
var
  Start: Int64;
begin
  if Root then
    Start := 0
  else
    Start := FBase + AFrom;
  if (AOffset < 0) or (Start mod 8 <> 0) then
    raise Error(pekRange, 'bad offset ' + IntToStr(AOffset) + ' (from bit ' + IntToStr(Start) + ')');
  Result := TPbWriter.Create;
  Result.FBase := Start + AOffset * 8;
  Result.CopyFrames(Self);
end;

procedure TPbWriter.Place(S: TPbWriter);
var
  N, I: Integer;
begin
  N := Length(FPlaced);
  SetLength(FPlaced, N + 1 + Length(S.FPlaced));
  FPlaced[N].At := S.FBase div 8;
  FPlaced[N].Data := S.ToBytes;
  FPlaced[N].Path := Path;
  for I := 0 to High(S.FPlaced) do
    FPlaced[N + 1 + I] := S.FPlaced[I];
end;

function TPbWriter.Finish: TBytes;
var
  I, J: Integer;
  K: Int64;
  T: TPbPlaced;
begin
  // Insertion sort by offset, stable like the other runtimes.
  for I := 1 to High(FPlaced) do
  begin
    T := FPlaced[I];
    J := I - 1;
    while (J >= 0) and (FPlaced[J].At > T.At) do
    begin
      FPlaced[J + 1] := FPlaced[J];
      Dec(J);
    end;
    FPlaced[J + 1] := T;
  end;
  for I := 0 to High(FPlaced) do
  begin
    // The output reaches the offset even when the packet is empty.
    while FLen < FPlaced[I].At do
      AddByte(0);
    for J := 0 to High(FPlaced[I].Data) do
    begin
      K := FPlaced[I].At + J;
      if K < FLen then
      begin
        if FBuf[K] <> FPlaced[I].Data[J] then
          raise EPbError.CreatePb(pekMismatch, 'the packet placed at byte ' + IntToStr(FPlaced[I].At) +
            ' does not match the bytes already there', FPlaced[I].Path, K * 8);
      end
      else
      begin
        while FLen < K do
          AddByte(0);
        AddByte(FPlaced[I].Data[J]);
      end;
    end;
  end;
  SetLength(FPlaced, 0);
  Result := ToBytes;
end;

procedure TPbWriter.WriteBits(Value: UInt64; Width: Integer);
var
  Left, Off, Take, Bits: Integer;
begin
  Left := Width;
  while Left > 0 do
  begin
    if FPos and 7 = 0 then
      AddByte(0);
    Off := FPos and 7;
    Take := 8 - Off;
    if Take > Left then
      Take := Left;
    Bits := (Value shr (Left - Take)) and UInt64((1 shl Take) - 1);
    FBuf[FLen - 1] := FBuf[FLen - 1] or Byte(Bits shl (8 - Off - Take));
    Inc(FPos, Take);
    Dec(Left, Take);
  end;
end;

procedure TPbWriter.WriteUint(Value: UInt64; NBytes: Integer; Little: Boolean);
var
  I, Shift: Integer;
begin
  for I := 0 to NBytes - 1 do
  begin
    if Little then
      Shift := 8 * I
    else
      Shift := 8 * (NBytes - 1 - I);
    AddByte(Byte(Value shr Shift));
  end;
  Inc(FPos, Int64(NBytes) * 8);
end;

procedure TPbWriter.WriteBytes(const Bytes: array of Byte);
var
  I: Integer;
begin
  for I := 0 to High(Bytes) do
    AddByte(Bytes[I]);
  Inc(FPos, Int64(Length(Bytes)) * 8);
end;

procedure TPbWriter.WriteZeroBits(Bits: Int64);
begin
  while Bits > 32 do
  begin
    WriteBits(0, 32);
    Dec(Bits, 32);
  end;
  if Bits > 0 then
    WriteBits(0, Bits);
end;

procedure TPbWriter.EndWindow(Start, Size: Int64; Exact: Boolean);
var
  Used: Int64;
begin
  Used := FPos - Start;
  if (Size < 0) or (Used > Size * 8) then
    raise Error(pekRange, 'the content takes ' + IntToStr(Used) + ' bit(s), more than its size of ' +
      IntToStr(Size) + ' byte(s)');
  if Exact and (Used <> Size * 8) then
    raise Error(pekMismatch, 'the content takes ' + IntToStr(Used) + ' bit(s) but must fill its ' +
      IntToStr(Size) + ' byte(s)');
  WriteZeroBits(Size * 8 - Used);
end;

procedure TPbWriter.PatchUint(AAt: Int64; Value: UInt64; NBytes: Integer; Little: Boolean);
var
  I, Shift: Integer;
begin
  for I := 0 to NBytes - 1 do
  begin
    if Little then
      Shift := 8 * I
    else
      Shift := 8 * (NBytes - 1 - I);
    FBuf[AAt div 8 + I] := Byte(Value shr Shift);
  end;
end;

procedure TPbWriter.PatchBits(AAt: Int64; Value: UInt64; Width: Integer);
var
  I, Bit, Off: Integer;
  B: Int64;
begin
  for I := 0 to Width - 1 do
  begin
    Bit := (Value shr (Width - 1 - I)) and 1;
    B := (AAt + I) div 8;
    Off := 7 - (AAt + I) mod 8;
    FBuf[B] := (FBuf[B] and not (1 shl Off)) or (Bit shl Off);
  end;
end;

function TPbWriter.Checksum(Algo: Integer; AFrom, ATo, HoleFrom, HoleTo: Int64): UInt64;
begin
  Result := PbChecksum(Algo, FBuf, AFrom div 8, ATo div 8, HoleFrom div 8, HoleTo div 8);
end;

function TPbWriter.Utf8Bytes(const S: string): TBytes;
var
  I, N: Integer;
  C, D: Cardinal;
begin
  SetLength(Result, Length(S) * 3);
  N := 0;
  I := 1;
  while I <= Length(S) do
  begin
    C := Ord(S[I]);
    if (C >= $D800) and (C <= $DFFF) then
    begin
      if (C > $DBFF) or (I = Length(S)) then
        raise Error(pekText, 'the string is not valid Unicode (unpaired surrogate)');
      D := Ord(S[I + 1]);
      if (D < $DC00) or (D > $DFFF) then
        raise Error(pekText, 'the string is not valid Unicode (unpaired surrogate)');
      C := $10000 + ((C - $D800) shl 10) + (D - $DC00);
      Inc(I);
    end;
    if C < $80 then
    begin
      Result[N] := C;
      Inc(N);
    end
    else if C < $800 then
    begin
      Result[N] := $C0 or (C shr 6);
      Result[N + 1] := $80 or (C and $3F);
      Inc(N, 2);
    end
    else if C < $10000 then
    begin
      Result[N] := $E0 or (C shr 12);
      Result[N + 1] := $80 or ((C shr 6) and $3F);
      Result[N + 2] := $80 or (C and $3F);
      Inc(N, 3);
    end
    else
    begin
      Result[N] := $F0 or (C shr 18);
      Result[N + 1] := $80 or ((C shr 12) and $3F);
      Result[N + 2] := $80 or ((C shr 6) and $3F);
      Result[N + 3] := $80 or (C and $3F);
      Inc(N, 4);
    end;
    Inc(I);
  end;
  SetLength(Result, N);
end;

function TPbWriter.TextBytes(const S: string; Enc: Integer): TBytes;
const
  Names: array[1..4] of string = ('ASCII', 'Latin-1', 'UTF-16', 'UTF-16');
var
  I: Integer;
  C, D: Cardinal;
begin
  if Enc = 0 then
    Exit(Utf8Bytes(S));
  if Enc >= 3 then
    SetLength(Result, 2 * Length(S))
  else
    SetLength(Result, Length(S));
  for I := 1 to Length(S) do
  begin
    C := Ord(S[I]);
    if ((Enc = 1) and (C > $7F)) or ((Enc = 2) and (C > $FF)) then
      raise Error(pekText, 'the string is not valid ' + Names[Enc]);
    if Enc >= 3 then
    begin
      // Surrogates must come in pairs.
      if (C >= $D800) and (C <= $DBFF) then
      begin
        if I = Length(S) then
          raise Error(pekText, 'the string is not valid ' + Names[Enc]);
        D := Ord(S[I + 1]);
        if (D < $DC00) or (D > $DFFF) then
          raise Error(pekText, 'the string is not valid ' + Names[Enc]);
      end
      else if (C >= $DC00) and (C <= $DFFF) then
        if (I = 1) or (Ord(S[I - 1]) < $D800) or (Ord(S[I - 1]) > $DBFF) then
          raise Error(pekText, 'the string is not valid ' + Names[Enc]);
      if Enc = 3 then
      begin
        Result[2 * I - 2] := Byte(C);
        Result[2 * I - 1] := Byte(C shr 8);
      end
      else
      begin
        Result[2 * I - 2] := Byte(C shr 8);
        Result[2 * I - 1] := Byte(C);
      end;
    end
    else
      Result[I - 1] := Byte(C);
  end;
end;

procedure TPbWriter.WriteVarint(Kind: Integer; V: UInt64);
var
  X: Int64;
  B: UInt64;
  Done: Boolean;
  Groups: array[0..9] of UInt64;
  N, I: Integer;
begin
  case Kind of
    5:
      if V < $80 then
        WriteUint(V, 1, False)
      else if V <= $7FFF then
        WriteUint(V or $8000, 2, False)
      else
        raise Error(pekRange, PbJsonU(V) + ' does not fit in a varint15');
    4:
      if V <= $3F then
        WriteUint(V, 1, False)
      else if V <= $3FFF then
        WriteUint(V or (UInt64(1) shl 14), 2, False)
      else if V <= $3FFFFFFF then
        WriteUint(V or (UInt64(2) shl 30), 4, False)
      else if V <= UInt64($3FFFFFFFFFFFFFFF) then
        WriteUint(V or (UInt64(3) shl 62), 8, False)
      else
        raise Error(pekRange, PbJsonU(V) + ' does not fit in a QUIC varint');
    1:
      begin
        X := Int64(V);
        repeat
          B := UInt64(X and $7F);
          X := PbShr(X, 7);
          Done := ((X = 0) and (B and $40 = 0)) or ((X = -1) and (B and $40 <> 0));
          if Done then
            WriteUint(B, 1, False)
          else
            WriteUint(B or $80, 1, False);
        until Done;
      end;
    3:
      begin
        Groups[0] := V and $7F;
        N := 1;
        V := V shr 7;
        while V <> 0 do
        begin
          Groups[N] := (V and $7F) or $80;
          Inc(N);
          V := V shr 7;
        end;
        for I := N - 1 downto 0 do
          WriteUint(Groups[I], 1, False);
      end;
  else
    if Kind = 2 then
      V := (V shl 1) xor UInt64(PbShr(Int64(V), 63));
    repeat
      B := V and $7F;
      V := V shr 7;
      if V <> 0 then
        WriteUint(B or $80, 1, False)
      else
        WriteUint(B, 1, False);
    until V = 0;
  end;
end;

procedure TPbWriter.CheckNoTerm(const Data, Term: array of Byte);
var
  I, K: Integer;
  Hit: Boolean;
begin
  I := 0;
  while I + Length(Term) <= Length(Data) do
  begin
    Hit := True;
    for K := 0 to High(Term) do
      if Data[I + K] <> Term[K] then
      begin
        Hit := False;
        Break;
      end;
    if Hit then
      raise Error(pekInvalid, 'the value contains its terminator');
    Inc(I);
  end;
end;

procedure TPbWriter.CheckFits(Length, Size: Int64);
begin
  if Length > Size then
    raise Error(pekRange, IntToStr(Length) + ' byte(s) do not fit in ' + IntToStr(Size));
end;

procedure TPbWriter.CheckNoNul(const Data: TBytes);
var
  I: Integer;
begin
  for I := 0 to High(Data) do
    if Data[I] = 0 then
      raise Error(pekText, 'the string contains a NUL byte');
end;

procedure TPbWriter.CheckLen(Actual, Expected: Int64);
begin
  if Actual <> Expected then
    raise Error(pekMismatch, IntToStr(Actual) + ' element(s) but the length expression says ' +
      IntToStr(Expected));
end;

procedure TPbWriter.CheckU(V: UInt64; Width: Integer);
begin
  if (Width < 64) and (V shr Width <> 0) then
    raise Error(pekRange, 'value ' + PbJsonU(V) + ' does not fit in ' + IntToStr(Width) + ' bit(s)');
end;

procedure TPbWriter.CheckI(V: Int64; Width: Integer);
begin
  if (Width < 64) and ((V < -(Int64(1) shl (Width - 1))) or (V > (Int64(1) shl (Width - 1)) - 1)) then
    raise Error(pekRange, 'value ' + IntToStr(V) + ' does not fit in ' + IntToStr(Width) + ' signed bit(s)');
end;

{ helpers }

function PbKindName(Kind: TPbErrorKind): string;
const
  Names: array[TPbErrorKind] of string = ('incomplete', 'invalid', 'range', 'text', 'mismatch', 'constraint');
begin
  Result := Names[Kind];
end;

function PbPad(Offset, Units: Int64): Int64;
begin
  Result := (Units - Offset mod Units) mod Units;
end;

function PbSext(V: UInt64; Width: Integer): Int64;
begin
  if (Width < 64) and ((V shr (Width - 1)) and 1 = 1) then
    V := V or (High(UInt64) shl Width);
  Result := Int64(V);
end;

function PbTrunc(V: Int64; Width: Integer; Signed: Boolean): Int64;
var
  U: UInt64;
begin
  if Width >= 64 then
    Exit(V);
  U := UInt64(V) and ((UInt64(1) shl Width) - 1);
  if Signed then
    Result := PbSext(U, Width)
  else
    Result := Int64(U);
end;

function PbDiv(A, B: Int64): Int64;
begin
  if B = 0 then
    Result := 0
  else if B = -1 then
    Result := Int64(UInt64(0) - UInt64(A))
  else
    Result := A div B;
end;

function PbMod(A, B: Int64): Int64;
begin
  if (B = 0) or (B = -1) then
    Result := 0
  else
    Result := A mod B;
end;

function PbShl(A, B: Int64): Int64;
begin
  if (B < 0) or (B > 63) then
    Result := 0
  else
    Result := Int64(UInt64(A) shl B);
end;

function PbShr(A, B: Int64): Int64;
begin
  // Arithmetic: `shr` is a logical shift in Pascal.
  if B < 0 then
    Exit(0);
  if B > 63 then
    B := 63;
  if A < 0 then
    Result := not Int64(UInt64(not A) shr B)
  else
    Result := Int64(UInt64(A) shr B);
end;

function PbPow(B, E: Int64): Int64;
var
  Acc: Int64;
  X: UInt64;
begin
  if E < 0 then
    Exit(0);
  Acc := 1;
  X := E;
  while X > 0 do
  begin
    if X and 1 = 1 then
      Acc := Acc * B;
    B := B * B;
    X := X shr 1;
  end;
  Result := Acc;
end;

function PbPowF(B, E: Double): Double;
begin
  Result := Power(B, E);
end;

function PbFtoI(V: Double): Int64;
begin
  if IsNan(V) then
    Result := 0
  else if V >= 9223372036854775807.0 then
    Result := High(Int64)
  else if V <= -9223372036854775808.0 then
    Result := Low(Int64)
  else
    Result := Trunc(V);
end;

function PbItoF(V: Int64): Double;
begin
  Result := V;
end;

function PbIfI(C: Boolean; A, B: Int64): Int64;
begin
  if C then Result := A else Result := B;
end;

function PbIfF(C: Boolean; A, B: Double): Double;
begin
  if C then Result := A else Result := B;
end;

function PbIfB(C: Boolean; A, B: Boolean): Boolean;
begin
  if C then Result := A else Result := B;
end;

function PbMinI(A, B: Int64): Int64;
begin
  if A < B then Result := A else Result := B;
end;

function PbMaxI(A, B: Int64): Int64;
begin
  if A > B then Result := A else Result := B;
end;

function PbMinF(A, B: Double): Double;
begin
  Result := Min(A, B);
end;

function PbMaxF(A, B: Double): Double;
begin
  Result := Max(A, B);
end;

function PbSqrt(V: Double): Double;
begin
  if V < 0 then
    Result := NaN
  else
    Result := Sqrt(V);
end;

function PbUtf8Len(const S: string): Int64;
var
  I: Integer;
  C: Cardinal;
begin
  Result := 0;
  for I := 1 to Length(S) do
  begin
    C := Ord(S[I]);
    if C < $80 then
      Inc(Result)
    else if C < $800 then
      Inc(Result, 2)
    else if (C >= $D800) and (C <= $DFFF) then
      Inc(Result, 2) // half of a 4-byte sequence
    else
      Inc(Result, 3);
  end;
end;

function PbAt(const A: TBytes; I: Int64): Int64;
begin
  if (I >= 0) and (I < Length(A)) then Result := A[I] else Result := 0;
end;

function PbAt(const A: TPbInt8Array; I: Int64): Int64;
begin
  if (I >= 0) and (I < Length(A)) then Result := A[I] else Result := 0;
end;

function PbAt(const A: TPbInt16Array; I: Int64): Int64;
begin
  if (I >= 0) and (I < Length(A)) then Result := A[I] else Result := 0;
end;

function PbAt(const A: TPbUInt16Array; I: Int64): Int64;
begin
  if (I >= 0) and (I < Length(A)) then Result := A[I] else Result := 0;
end;

function PbAt(const A: TPbInt32Array; I: Int64): Int64;
begin
  if (I >= 0) and (I < Length(A)) then Result := A[I] else Result := 0;
end;

function PbAt(const A: TPbUInt32Array; I: Int64): Int64;
begin
  if (I >= 0) and (I < Length(A)) then Result := A[I] else Result := 0;
end;

function PbAt(const A: TPbInt64Array; I: Int64): Int64;
begin
  if (I >= 0) and (I < Length(A)) then Result := A[I] else Result := 0;
end;

function PbAt(const A: TPbUInt64Array; I: Int64): Int64;
begin
  if (I >= 0) and (I < Length(A)) then Result := Int64(A[I]) else Result := 0;
end;

function PbAt(const A: TPbSingleArray; I: Int64): Double;
begin
  if (I >= 0) and (I < Length(A)) then Result := A[I] else Result := 0;
end;

function PbAt(const A: TPbDoubleArray; I: Int64): Double;
begin
  if (I >= 0) and (I < Length(A)) then Result := A[I] else Result := 0;
end;

function PbSum(const A: TBytes): Int64;
var I: Integer;
begin
  Result := 0;
  for I := 0 to High(A) do Result := Result + A[I];
end;

function PbSum(const A: TPbInt8Array): Int64;
var I: Integer;
begin
  Result := 0;
  for I := 0 to High(A) do Result := Result + A[I];
end;

function PbSum(const A: TPbInt16Array): Int64;
var I: Integer;
begin
  Result := 0;
  for I := 0 to High(A) do Result := Result + A[I];
end;

function PbSum(const A: TPbUInt16Array): Int64;
var I: Integer;
begin
  Result := 0;
  for I := 0 to High(A) do Result := Result + A[I];
end;

function PbSum(const A: TPbInt32Array): Int64;
var I: Integer;
begin
  Result := 0;
  for I := 0 to High(A) do Result := Result + A[I];
end;

function PbSum(const A: TPbUInt32Array): Int64;
var I: Integer;
begin
  Result := 0;
  for I := 0 to High(A) do Result := Result + A[I];
end;

function PbSum(const A: TPbInt64Array): Int64;
var I: Integer;
begin
  Result := 0;
  for I := 0 to High(A) do Result := Result + A[I];
end;

function PbSum(const A: TPbUInt64Array): Int64;
var I: Integer;
begin
  Result := 0;
  for I := 0 to High(A) do Result := Result + Int64(A[I]);
end;

function PbSum(const A: TPbSingleArray): Double;
var I: Integer;
begin
  Result := 0;
  for I := 0 to High(A) do Result := Result + A[I];
end;

function PbSum(const A: TPbDoubleArray): Double;
var I: Integer;
begin
  Result := 0;
  for I := 0 to High(A) do Result := Result + A[I];
end;

function PbProduct(const A: TBytes): Int64;
var I: Integer;
begin
  Result := 1;
  for I := 0 to High(A) do Result := Result * A[I];
end;

function PbProduct(const A: TPbInt8Array): Int64;
var I: Integer;
begin
  Result := 1;
  for I := 0 to High(A) do Result := Result * A[I];
end;

function PbProduct(const A: TPbInt16Array): Int64;
var I: Integer;
begin
  Result := 1;
  for I := 0 to High(A) do Result := Result * A[I];
end;

function PbProduct(const A: TPbUInt16Array): Int64;
var I: Integer;
begin
  Result := 1;
  for I := 0 to High(A) do Result := Result * A[I];
end;

function PbProduct(const A: TPbInt32Array): Int64;
var I: Integer;
begin
  Result := 1;
  for I := 0 to High(A) do Result := Result * A[I];
end;

function PbProduct(const A: TPbUInt32Array): Int64;
var I: Integer;
begin
  Result := 1;
  for I := 0 to High(A) do Result := Result * A[I];
end;

function PbProduct(const A: TPbInt64Array): Int64;
var I: Integer;
begin
  Result := 1;
  for I := 0 to High(A) do Result := Result * A[I];
end;

function PbProduct(const A: TPbUInt64Array): Int64;
var I: Integer;
begin
  Result := 1;
  for I := 0 to High(A) do Result := Result * Int64(A[I]);
end;

function PbProduct(const A: TPbSingleArray): Double;
var I: Integer;
begin
  Result := 1;
  for I := 0 to High(A) do Result := Result * A[I];
end;

function PbProduct(const A: TPbDoubleArray): Double;
var I: Integer;
begin
  Result := 1;
  for I := 0 to High(A) do Result := Result * A[I];
end;

function PbJsonHex(const B: TBytes): string;
const
  Digits: string = '0123456789abcdef';
var
  I: Integer;
begin
  SetLength(Result, 2 * Length(B) + 2);
  Result[1] := '"';
  for I := 0 to High(B) do
  begin
    Result[2 * I + 2] := Digits[B[I] shr 4 + 1];
    Result[2 * I + 3] := Digits[B[I] and 15 + 1];
  end;
  Result[Length(Result)] := '"';
end;

function PbJsonStr(const S: string): string;
var
  I: Integer;
  C: Cardinal;
begin
  Result := '"';
  for I := 1 to Length(S) do
  begin
    C := Ord(S[I]);
    if C = Ord('"') then
      Result := Result + '\"'
    else if C = Ord('\') then
      Result := Result + '\\'
    else if (C < $20) or (C > $7E) then
      Result := Result + '\u' + LowerCase(IntToHex(C, 4))
    else
      Result := Result + S[I];
  end;
  Result := Result + '"';
end;

function PbJsonI(V: Int64): string;
begin
  Result := IntToStr(V);
end;

function PbJsonU(V: UInt64): string;
var
  D: Integer;
begin
  if V = 0 then
    Exit('0');
  Result := '';
  while V > 0 do
  begin
    D := V mod 10;
    Result := Char(Ord('0') + D) + Result;
    V := V div 10;
  end;
end;

function PbJsonF(V: Double): string;
var
  F: TFormatSettings;
begin
  F := FormatSettings;
  F.DecimalSeparator := '.';
  Result := FloatToStrF(V, ffGeneral, 17, 0, F);
end;

type
  TPbCrc = record
    Width: Integer;
    Poly, Init: UInt64;
    Reflected: Boolean;
    XorOut: UInt64;
  end;

const
  // CRC parameters by algorithm number: width, polynomial (reflected for
  // reflected CRCs), initial value, reflected, final XOR.
  PbCrcs: array[0..7] of TPbCrc = (
    (Width: 8; Poly: $07; Init: 0; Reflected: False; XorOut: 0),                            // crc8 (CRC-8/SMBUS)
    (Width: 16; Poly: $A001; Init: 0; Reflected: True; XorOut: 0),                          // crc16_arc
    (Width: 16; Poly: $1021; Init: $FFFF; Reflected: False; XorOut: 0),                     // crc16_ccitt_false
    (Width: 16; Poly: $1021; Init: 0; Reflected: False; XorOut: 0),                         // crc16_xmodem
    (Width: 16; Poly: $8408; Init: 0; Reflected: True; XorOut: 0),                          // crc16_kermit
    (Width: 16; Poly: $A001; Init: $FFFF; Reflected: True; XorOut: 0),                      // crc16_modbus
    (Width: 32; Poly: $EDB88320; Init: $FFFFFFFF; Reflected: True; XorOut: $FFFFFFFF),     // crc32
    (Width: 32; Poly: $82F63B78; Init: $FFFFFFFF; Reflected: True; XorOut: $FFFFFFFF)      // crc32c
  );

function PbChecksum(Algo: Integer; const Buf: TBytes; AFrom, ATo, HoleFrom, HoleTo: Int64): UInt64;
var
  I: Int64;
  K: Integer;
  X, A, B, Mask, Crc: UInt64;
  P: TPbCrc;
begin
  if Algo < 8 then
  begin
    P := PbCrcs[Algo];
    Mask := (UInt64(1) shl P.Width) - 1;
    Crc := P.Init;
    for I := AFrom to ATo - 1 do
    begin
      if (I >= HoleFrom) and (I < HoleTo) then X := 0 else X := Buf[I];
      if P.Reflected then
      begin
        Crc := Crc xor X;
        for K := 0 to 7 do
          if Crc and 1 <> 0 then Crc := (Crc shr 1) xor P.Poly else Crc := Crc shr 1;
      end
      else
      begin
        Crc := Crc xor (X shl (P.Width - 8));
        for K := 0 to 7 do
          if Crc and (UInt64(1) shl (P.Width - 1)) <> 0 then
            Crc := ((Crc shl 1) xor P.Poly) and Mask
          else
            Crc := (Crc shl 1) and Mask;
      end;
    end;
    Exit((Crc xor P.XorOut) and Mask);
  end;
  A := 0;
  B := 0;
  for I := AFrom to ATo - 1 do
  begin
    if (I >= HoleFrom) and (I < HoleTo) then X := 0 else X := Buf[I];
    case Algo of
      8: if (I - AFrom) mod 2 = 0 then A := A + (X shl 8) else A := A + X;
      9:
        begin
          A := (A + X) mod 255;
          B := (B + A) mod 255;
        end;
      10: A := (A + X) and $FF;
      12: A := (A + X) and $FFFF;
      13: A := (A + (X shl (8 * (3 - (I - AFrom) mod 4)))) and $FFFFFFFF;
    else
      A := A xor X;
    end;
  end;
  if Algo = 8 then
  begin
    while A shr 16 <> 0 do
      A := (A and $FFFF) + (A shr 16);
    Exit(not A and $FFFF);
  end;
  if Algo = 13 then
    Exit(((A shr 16) + (A and $FFFF)) and $FFFF);
  if Algo = 9 then
    Result := (B shl 8) or A
  else
    Result := A;
end;

function PbZeros(N: Integer): TBytes;
begin
  SetLength(Result, N);
  if N > 0 then
    FillChar(Result[0], N, 0);
end;

function PbBitsToSingle(V: UInt64): Single;
var
  U: UInt32;
begin
  U := UInt32(V);
  Move(U, Result, 4);
end;

function PbBitsToDouble(V: UInt64): Double;
begin
  Move(V, Result, 8);
end;

function PbSingleToBits(V: Single): UInt64;
var
  U: UInt32;
begin
  Move(V, U, 4);
  Result := U;
end;

function PbDoubleToBits(V: Double): UInt64;
begin
  Move(V, Result, 8);
end;

// ---- generated packets --------------------------------------------------
