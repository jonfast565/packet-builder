   -- ---- packet-builder runtime -------------------------------------------

   package Pb_SU renames Ada.Strings.Unbounded;
   use type Pb_SU.Unbounded_String;

   --  The deepest packet nesting accepted.
   Pb_Max_Depth : constant := 64;

   --  Raised when data cannot be decoded or a value cannot be encoded;
   --  Last_Error says what went wrong and where. Generated code raises no
   --  other exception.
   Pb_Error : exception;

   --  What went wrong while decoding or encoding.
   type Pb_Error_Kind is
     (Pb_Incomplete,  --  the input ended before the packet did
      Pb_Invalid,     --  malformed data: a bad length, nesting too deep, ...
      Pb_Range,       --  a value does not fit in its field
      Pb_Text,        --  a string is not valid text, or holds a NUL
      Pb_Mismatch,    --  a length, derived field or checksum does not match
      Pb_Constraint); --  a value breaks a declared constraint

   type Pb_Error_Info is record
      Kind        : Pb_Error_Kind := Pb_Invalid;
      --  Where it happened: Packet.field[index].field.
      Path        : Pb_SU.Unbounded_String;
      Bit_Offset  : Integer_64 := 0;
      --  For Pb_Incomplete: the least number of extra input bits needed.
      Needed_Bits : Integer_64 := 0;
      Reason      : Pb_SU.Unbounded_String;
      Message     : Pb_SU.Unbounded_String;
   end record;

   --  The details of the last Pb_Error raised (one record for the whole
   --  program: not task-safe).
   function Last_Error return Pb_Error_Info;

   --  incomplete, invalid, range, text, mismatch or constraint.
   function Pb_Kind_Name (K : Pb_Error_Kind) return String;

   --  Record the details and raise Pb_Error.
   procedure Pb_Raise
     (Kind        : Pb_Error_Kind;
      Reason      : String;
      Path        : String;
      Bit_Offset  : Integer_64;
      Needed_Bits : Integer_64 := 0)
     with No_Return;

   type Pb_Byte_Array is array (Natural range <>) of Unsigned_8;
   type Pb_Mac is array (0 .. 5) of Unsigned_8;

   package Pb_U8_Vectors is new Ada.Containers.Vectors (Natural, Unsigned_8);
   package Pb_I8_Vectors is new Ada.Containers.Vectors (Natural, Integer_8);
   package Pb_U16_Vectors is new Ada.Containers.Vectors (Natural, Unsigned_16);
   package Pb_I16_Vectors is new Ada.Containers.Vectors (Natural, Integer_16);
   package Pb_U32_Vectors is new Ada.Containers.Vectors (Natural, Unsigned_32);
   package Pb_I32_Vectors is new Ada.Containers.Vectors (Natural, Integer_32);
   package Pb_U64_Vectors is new Ada.Containers.Vectors (Natural, Unsigned_64);
   package Pb_I64_Vectors is new Ada.Containers.Vectors (Natural, Integer_64);
   package Pb_F32_Vectors is new Ada.Containers.Vectors (Natural, IEEE_Float_32);
   package Pb_F64_Vectors is new Ada.Containers.Vectors (Natural, IEEE_Float_64);
   package Pb_Str_Vectors is new Ada.Containers.Vectors (Natural, Pb_SU.Unbounded_String);
   package Pb_Mac_Vectors is new Ada.Containers.Vectors (Natural, Pb_Mac);

   --  Byte strings held by packets.
   subtype Pb_Bytes is Pb_U8_Vectors.Vector;

   function Pb_Vec (A : Pb_Byte_Array) return Pb_Bytes;
   function Pb_Arr (V : Pb_Bytes) return Pb_Byte_Array;

   --  The packets being decoded or encoded, innermost last, each with the
   --  field it is working on: the path reported in errors.
   type Pb_Frame is record
      Packet : Pb_SU.Unbounded_String;
      Field  : Pb_SU.Unbounded_String;
      Index  : Integer_64 := -1;
   end record;

   type Pb_Frame_Array is array (1 .. Pb_Max_Depth + 1) of Pb_Frame;

   type Pb_Trace is record
      Frames  : Pb_Frame_Array;
      Depth   : Natural := 0;
      Pos     : Integer_64 := 0;  --  in bits
      Version : Integer_64 := 0;  --  protocol version; 0 until set
   end record;

   -- @versions{
   --  A version scope left for another, and its version.
   type Pb_Scope_Left is record
      Scope   : Natural := 0;
      Version : Integer_64 := 0;
   end record;

   type Pb_Scope_Array is array (1 .. Pb_Max_Depth + 1) of Pb_Scope_Left;

   --  The version scope being coded (plus 1; 0 before any) and the scopes
   --  left for it, innermost last.
   type Pb_Scopes is record
      Scope : Natural := 0;
      Left  : Pb_Scope_Array;
      Depth : Natural := 0;
   end record;

   -- @versions}
   type Pb_Byte_Array_Access is access Pb_Byte_Array;
   type Pb_Flags is array (Natural range <>) of Boolean;
   type Pb_Flags_Access is access Pb_Flags;

   --  Input read on demand (a file, a stream that can seek): Size bytes,
   --  loaded a page at a time by Pb_Fetch. Only the pages a decode touches
   --  are fetched: fields a view skips are never read. Derive a type that
   --  overrides Pb_Fetch, call Pb_Open, then decode with Decode_From on a
   --  Pb_Reader (0) set up by Pb_Init (Reader, Source). Pages stay loaded
   --  while the source lives.
   type Pb_Source is abstract new Ada.Finalization.Limited_Controlled with record
      Size   : Natural := 0;
      Page   : Positive := 4096;
      Buf    : Pb_Byte_Array_Access;  --  the input (0-based), zeros until loaded
      Loaded : Pb_Flags_Access;       --  one flag per page
   end record;

   --  Fill Buf with the input bytes at Offset (0-based). To fail, raise any
   --  exception: the reader reports its message.
   procedure Pb_Fetch (S : in out Pb_Source; Offset : Integer_64; Buf : out Pb_Byte_Array) is abstract;

   --  Make S a source of Size bytes, read in pages of Page bytes.
   procedure Pb_Open (S : in out Pb_Source'Class; Size : Natural; Page : Positive := 4096);

   overriding procedure Finalize (S : in out Pb_Source);

   --  Reads Len bytes (a copy of the input), or a source (with Len 0).
   type Pb_Reader (Len : Natural) is limited record
      T       : Pb_Trace;
      Data    : Pb_Byte_Array (1 .. Len);
      Src     : access Pb_Source'Class;  --  null when reading Data
      Size    : Integer_64 := 0;         --  input size in bytes
      Limit   : Integer_64 := 0;
      Windows : Natural := 0;
      -- @versions{
      Sc      : Pb_Scopes;
      -- @versions}
   end record;

   type Pb_Jump_State is record
      Pos     : Integer_64 := 0;
      Limit   : Integer_64 := 0;
      Windows : Natural := 0;
   end record;

   --  Bytes a sub-writer placed at an offset (`at` fields).
   type Pb_Placed is record
      At_Byte : Integer_64 := 0;
      Data    : Pb_Bytes;
      Path    : Pb_SU.Unbounded_String;
   end record;

   package Pb_Placed_Vectors is new Ada.Containers.Vectors (Natural, Pb_Placed);

   type Pb_Writer is limited record
      T      : Pb_Trace;
      Buf    : Pb_Bytes;
      Base   : Integer_64 := 0;
      Placed : Pb_Placed_Vectors.Vector;
      -- @versions{
      Sc     : Pb_Scopes;
      -- @versions}
   end record;

   --  Start reading Data.
   procedure Pb_Init (R : in out Pb_Reader; Data : Pb_Byte_Array);

   --  Start reading Src (R is a Pb_Reader (0)), which must outlive R.
   procedure Pb_Init (R : in out Pb_Reader; Src : in out Pb_Source'Class);

   --  JSON spellings (used by To_Json).
   function Pb_Json_Hex (B : Pb_Byte_Array) return String;
   function Pb_Json_Hex (B : Pb_Bytes) return String;
   function Pb_Json_Mac (M : Pb_Mac) return String;
   function Pb_Json_Str (S : String) return String;
   function Pb_Json_Str (S : Pb_SU.Unbounded_String) return String;
   function Pb_Json_I (V : Integer_64) return String;
   function Pb_Json_U (V : Unsigned_64) return String;
   function Pb_Json_F (V : IEEE_Float_64) return String;

   -- @implementation

   -- ---- packet-builder runtime -------------------------------------------

   Pb_Last : Pb_Error_Info;

   function Last_Error return Pb_Error_Info is (Pb_Last);

   function Pb_Kind_Name (K : Pb_Error_Kind) return String is
   begin
      case K is
         when Pb_Incomplete => return "incomplete";
         when Pb_Invalid => return "invalid";
         when Pb_Range => return "range";
         when Pb_Text => return "text";
         when Pb_Mismatch => return "mismatch";
         when Pb_Constraint => return "constraint";
      end case;
   end Pb_Kind_Name;

   function Pb_Img (V : Integer_64) return String is
      S : constant String := Integer_64'Image (V);
   begin
      if S (S'First) = ' ' then
         return S (S'First + 1 .. S'Last);
      end if;
      return S;
   end Pb_Img;

   function Pb_Img_U (V : Unsigned_64) return String is
      S : constant String := Unsigned_64'Image (V);
   begin
      if S (S'First) = ' ' then
         return S (S'First + 1 .. S'Last);
      end if;
      return S;
   end Pb_Img_U;

   procedure Pb_Raise
     (Kind        : Pb_Error_Kind;
      Reason      : String;
      Path        : String;
      Bit_Offset  : Integer_64;
      Needed_Bits : Integer_64 := 0)
   is
      Msg : constant String :=
        (if Path = "" then "" else Path & ": ") & Reason & " (at bit " & Pb_Img (Bit_Offset) & ")";
   begin
      Pb_Last :=
        (Kind        => Kind,
         Path        => Pb_SU.To_Unbounded_String (Path),
         Bit_Offset  => Bit_Offset,
         Needed_Bits => Needed_Bits,
         Reason      => Pb_SU.To_Unbounded_String (Reason),
         Message     => Pb_SU.To_Unbounded_String (Msg));
      raise Pb_Error with Msg;
   end Pb_Raise;

   --  Any other exception (a bug in the generated code or the runtime, or
   --  running out of memory) leaves the public entry points as Pb_Error.
   procedure Pb_Internal (E : Ada.Exceptions.Exception_Occurrence) with No_Return;

   procedure Pb_Internal (E : Ada.Exceptions.Exception_Occurrence) is
   begin
      Pb_Raise (Pb_Invalid, "internal error: " & Ada.Exceptions.Exception_Name (E), "", 0);
   end Pb_Internal;

   function Pb_Vec (A : Pb_Byte_Array) return Pb_Bytes is
      V : Pb_Bytes;
   begin
      V.Reserve_Capacity (Ada.Containers.Count_Type (A'Length));
      for X of A loop
         V.Append (X);
      end loop;
      return V;
   end Pb_Vec;

   function Pb_Arr (V : Pb_Bytes) return Pb_Byte_Array is
      A : Pb_Byte_Array (0 .. Natural (V.Length) - 1);
   begin
      for I in A'Range loop
         A (I) := V.Element (I);
      end loop;
      return A;
   end Pb_Arr;

   function Pb_Str_Bytes (S : String) return Pb_Byte_Array is
      A : Pb_Byte_Array (0 .. S'Length - 1);
   begin
      for I in A'Range loop
         A (I) := Unsigned_8 (Character'Pos (S (S'First + I)));
      end loop;
      return A;
   end Pb_Str_Bytes;

   function Pb_Bytes_Str (A : Pb_Byte_Array) return String is
      S : String (1 .. A'Length);
   begin
      for I in S'Range loop
         S (I) := Character'Val (Natural (A (A'First + I - 1)));
      end loop;
      return S;
   end Pb_Bytes_Str;

   -- ---- integers -----------------------------------------------------------

   function Pb_U2I is new Ada.Unchecked_Conversion (Unsigned_64, Integer_64);
   function Pb_I2U is new Ada.Unchecked_Conversion (Integer_64, Unsigned_64);

   --  Integer expressions are Integer_64 and wrap like two's complement.
   function Pb_Add (A, B : Integer_64) return Integer_64 is (Pb_U2I (Pb_I2U (A) + Pb_I2U (B)));
   function Pb_Minus (A, B : Integer_64) return Integer_64 is (Pb_U2I (Pb_I2U (A) - Pb_I2U (B)));
   function Pb_Mul (A, B : Integer_64) return Integer_64 is (Pb_U2I (Pb_I2U (A) * Pb_I2U (B)));
   function Pb_Neg (A : Integer_64) return Integer_64 is (Pb_U2I (0 - Pb_I2U (A)));
   function Pb_And (A, B : Integer_64) return Integer_64 is (Pb_U2I (Pb_I2U (A) and Pb_I2U (B)));
   function Pb_Or (A, B : Integer_64) return Integer_64 is (Pb_U2I (Pb_I2U (A) or Pb_I2U (B)));
   function Pb_Xor (A, B : Integer_64) return Integer_64 is (Pb_U2I (Pb_I2U (A) xor Pb_I2U (B)));
   function Pb_Not (A : Integer_64) return Integer_64 is (Pb_U2I (not Pb_I2U (A)));

   --  Division by zero is 0; the one overflowing quotient wraps.
   function Pb_Div (A, B : Integer_64) return Integer_64 is
     (if B = 0 then 0 elsif B = -1 then Pb_Neg (A) else A / B);

   function Pb_Rem (A, B : Integer_64) return Integer_64 is
     (if B = 0 or else B = -1 then 0 else A rem B);

   function Pb_Shl (A, B : Integer_64) return Integer_64 is
     (if B < 0 or else B > 63 then 0 else Pb_U2I (Shift_Left (Pb_I2U (A), Natural (B))));

   --  Arithmetic shift; shifts past 63 give the sign.
   function Pb_Shr (A, B : Integer_64) return Integer_64 is
     (if B < 0 then 0
      else Pb_U2I (Shift_Right_Arithmetic (Pb_I2U (A), Natural (Integer_64'Min (B, 63)))));

   function Pb_Pow (B, E : Integer_64) return Integer_64 is
      Acc : Unsigned_64 := 1;
      X   : Unsigned_64 := Pb_I2U (B);
      N   : Integer_64 := E;
   begin
      if E < 0 then
         return 0;
      end if;
      while N > 0 loop
         if N mod 2 = 1 then
            Acc := Acc * X;
         end if;
         X := X * X;
         N := N / 2;
      end loop;
      return Pb_U2I (Acc);
   end Pb_Pow;

   --  Bits to skip from Offset to the next multiple of Units.
   function Pb_Pad (Offset, Units : Integer_64) return Integer_64 is
     (if Units <= 0 then 0 else (Units - Offset rem Units) rem Units);

   --  The low Width bits of V as a signed number.
   function Pb_Sext (V : Unsigned_64; Width : Natural) return Integer_64 is
     (if Width > 0 and then Width < 64 and then (Shift_Right (V, Width - 1) and 1) = 1
      then Pb_U2I (V or Shift_Left (Unsigned_64'Last, Width))
      else Pb_U2I (V));

   function Pb_Trunc_U (V : Integer_64; Width : Natural) return Unsigned_64 is
     (if Width >= 64 then Pb_I2U (V) else Pb_I2U (V) and (Shift_Left (1, Width) - 1));

   --  V cut to Width bits, sign-extended when Signed.
   function Pb_Trunc (V : Integer_64; Width : Natural; Signed : Boolean) return Integer_64 is
     (if Width >= 64 then V
      elsif Signed then Pb_Sext (Pb_Trunc_U (V, Width), Width)
      else Pb_U2I (Pb_Trunc_U (V, Width)));

   function Pb_To_U8 (V : Unsigned_64) return Unsigned_8 is (Unsigned_8 (V and 16#FF#));
   function Pb_To_U16 (V : Unsigned_64) return Unsigned_16 is (Unsigned_16 (V and 16#FFFF#));
   function Pb_To_U32 (V : Unsigned_64) return Unsigned_32 is (Unsigned_32 (V and 16#FFFF_FFFF#));
   function Pb_To_I8 (V : Integer_64) return Integer_8 is (Integer_8 (Pb_Trunc (V, 8, True)));
   function Pb_To_I16 (V : Integer_64) return Integer_16 is (Integer_16 (Pb_Trunc (V, 16, True)));
   function Pb_To_I32 (V : Integer_64) return Integer_32 is (Integer_32 (Pb_Trunc (V, 32, True)));

   --  Any stored integer as Integer_64 (Unsigned_64 wraps).
   function Pb_I (X : Unsigned_8) return Integer_64 is (Integer_64 (X));
   function Pb_I (X : Unsigned_16) return Integer_64 is (Integer_64 (X));
   function Pb_I (X : Unsigned_32) return Integer_64 is (Integer_64 (X));
   function Pb_I (X : Unsigned_64) return Integer_64 is (Pb_U2I (X));
   function Pb_I (X : Integer_8) return Integer_64 is (Integer_64 (X));
   function Pb_I (X : Integer_16) return Integer_64 is (Integer_64 (X));
   function Pb_I (X : Integer_32) return Integer_64 is (Integer_64 (X));
   function Pb_I (X : Integer_64) return Integer_64 is (X);

   --  Any stored integer as its 64-bit two's complement pattern.
   function Pb_U (X : Unsigned_8) return Unsigned_64 is (Unsigned_64 (X));
   function Pb_U (X : Unsigned_16) return Unsigned_64 is (Unsigned_64 (X));
   function Pb_U (X : Unsigned_32) return Unsigned_64 is (Unsigned_64 (X));
   function Pb_U (X : Unsigned_64) return Unsigned_64 is (X);
   function Pb_U (X : Integer_8) return Unsigned_64 is (Pb_I2U (Integer_64 (X)));
   function Pb_U (X : Integer_16) return Unsigned_64 is (Pb_I2U (Integer_64 (X)));
   function Pb_U (X : Integer_32) return Unsigned_64 is (Pb_I2U (Integer_64 (X)));
   function Pb_U (X : Integer_64) return Unsigned_64 is (Pb_I2U (X));

   -- ---- floats -------------------------------------------------------------

   function Pb_U32_To_F32 is new Ada.Unchecked_Conversion (Unsigned_32, IEEE_Float_32);
   function Pb_F32_To_U32 is new Ada.Unchecked_Conversion (IEEE_Float_32, Unsigned_32);
   function Pb_U64_To_F64 is new Ada.Unchecked_Conversion (Unsigned_64, IEEE_Float_64);
   function Pb_F64_To_U64 is new Ada.Unchecked_Conversion (IEEE_Float_64, Unsigned_64);

   package Pb_EF is new Ada.Numerics.Generic_Elementary_Functions (IEEE_Float_64);
   package Pb_FIO is new Ada.Text_IO.Float_IO (IEEE_Float_64);

   function Pb_Bits_To_F32 (V : Unsigned_64) return IEEE_Float_32 is
     (Pb_U32_To_F32 (Unsigned_32 (V and 16#FFFF_FFFF#)));
   function Pb_Bits_To_F64 (V : Unsigned_64) return IEEE_Float_64 is (Pb_U64_To_F64 (V));
   function Pb_F32_Bits (V : IEEE_Float_32) return Unsigned_64 is (Unsigned_64 (Pb_F32_To_U32 (V)));
   function Pb_F64_Bits (V : IEEE_Float_64) return Unsigned_64 is (Pb_F64_To_U64 (V));

   Pb_NaN   : constant IEEE_Float_64 := Pb_U64_To_F64 (16#7FF8_0000_0000_0000#);
   Pb_Inf   : constant IEEE_Float_64 := Pb_U64_To_F64 (16#7FF0_0000_0000_0000#);
   Pb_NInf  : constant IEEE_Float_64 := Pb_U64_To_F64 (16#FFF0_0000_0000_0000#);
   Pb_NaN32 : constant IEEE_Float_32 := Pb_U32_To_F32 (16#7FC0_0000#);
   Pb_Inf32 : constant IEEE_Float_32 := Pb_U32_To_F32 (16#7F80_0000#);
   Pb_NInf32 : constant IEEE_Float_32 := Pb_U32_To_F32 (16#FF80_0000#);

   function Pb_Is_Nan (X : IEEE_Float_64) return Boolean is
     ((Pb_F64_Bits (X) and 16#7FF0_0000_0000_0000#) = 16#7FF0_0000_0000_0000#
      and then (Pb_F64_Bits (X) and 16#000F_FFFF_FFFF_FFFF#) /= 0);

   function Pb_Is_Finite (X : IEEE_Float_64) return Boolean is
     ((Pb_F64_Bits (X) and 16#7FF0_0000_0000_0000#) /= 16#7FF0_0000_0000_0000#);

   function Pb_Is_Negative (X : IEEE_Float_64) return Boolean is
     ((Pb_F64_Bits (X) and 16#8000_0000_0000_0000#) /= 0);

   --  Widen without a range check, so NaN and infinities survive.
   function Pb_F (X : IEEE_Float_32) return IEEE_Float_64 is
      B : constant Unsigned_32 := Pb_F32_To_U32 (X);
   begin
      if (B and 16#7F80_0000#) = 16#7F80_0000# then
         if (B and 16#007F_FFFF#) /= 0 then
            return Pb_NaN;
         elsif (B and 16#8000_0000#) /= 0 then
            return Pb_NInf;
         else
            return Pb_Inf;
         end if;
      end if;
      return IEEE_Float_64 (X);
   end Pb_F;

   function Pb_F (X : IEEE_Float_64) return IEEE_Float_64 is (X);

   function Pb_To_F32 (X : IEEE_Float_64) return IEEE_Float_32 is
   begin
      if Pb_Is_Nan (X) then
         return Pb_NaN32;
      elsif X > IEEE_Float_64 (IEEE_Float_32'Last) then
         return Pb_Inf32;
      elsif X < IEEE_Float_64 (IEEE_Float_32'First) then
         return Pb_NInf32;
      end if;
      return IEEE_Float_32 (X);
   end Pb_To_F32;

   --  Float to integer: truncated, NaN is 0, saturated at the ends.
   function Pb_Ftoi (X : IEEE_Float_64) return Integer_64 is
   begin
      if Pb_Is_Nan (X) then
         return 0;
      elsif X >= 9.223372036854775807E18 then
         return Integer_64'Last;
      elsif X <= -9.223372036854775808E18 then
         return Integer_64'First;
      end if;
      return Integer_64 (IEEE_Float_64'Truncation (X));
   end Pb_Ftoi;

   function Pb_Div_F (A, B : IEEE_Float_64) return IEEE_Float_64 is
   begin
      if Pb_Is_Nan (A) or else Pb_Is_Nan (B) then
         return Pb_NaN;
      elsif B = 0.0 then
         if A = 0.0 then
            return Pb_NaN;
         elsif (A < 0.0) = Pb_Is_Negative (B) then
            return Pb_Inf;
         else
            return Pb_NInf;
         end if;
      elsif not Pb_Is_Finite (A) then
         if not Pb_Is_Finite (B) then
            return Pb_NaN;
         elsif (A < 0.0) = (B < 0.0) then
            return Pb_Inf;
         else
            return Pb_NInf;
         end if;
      elsif not Pb_Is_Finite (B) then
         return 0.0;
      end if;
      return A / B;
   end Pb_Div_F;

   function Pb_Sqrt (X : IEEE_Float_64) return IEEE_Float_64 is
   begin
      if Pb_Is_Nan (X) or else X < 0.0 then
         return Pb_NaN;
      elsif not Pb_Is_Finite (X) then
         return X;
      end if;
      return Pb_EF.Sqrt (X);
   end Pb_Sqrt;

   function Pb_Is_Odd (E : IEEE_Float_64) return Boolean is
     (Pb_Is_Finite (E) and then E = IEEE_Float_64'Truncation (E)
      and then IEEE_Float_64'Remainder (E, 2.0) /= 0.0);

   --  B ** E with the special cases of C's pow.
   function Pb_Pow_F (B, E : IEEE_Float_64) return IEEE_Float_64 is
      Mag : IEEE_Float_64;
      Neg : Boolean := False;
   begin
      if E = 0.0 or else B = 1.0 then
         return 1.0;
      elsif Pb_Is_Nan (B) or else Pb_Is_Nan (E) then
         return Pb_NaN;
      elsif not Pb_Is_Finite (E) then
         if abs B = 1.0 then
            return 1.0;
         elsif (abs B > 1.0) = (E > 0.0) then
            return Pb_Inf;
         else
            return 0.0;
         end if;
      elsif not Pb_Is_Finite (B) then
         Neg := B < 0.0 and then Pb_Is_Odd (E);
         if E > 0.0 then
            return (if Neg then Pb_NInf else Pb_Inf);
         else
            return (if Neg then -0.0 else 0.0);
         end if;
      elsif B = 0.0 then
         Neg := Pb_Is_Negative (B) and then Pb_Is_Odd (E);
         if E > 0.0 then
            return (if Neg then -0.0 else 0.0);
         else
            return (if Neg then Pb_NInf else Pb_Inf);
         end if;
      end if;
      Mag := B;
      if B < 0.0 then
         if E /= IEEE_Float_64'Truncation (E) then
            return Pb_NaN;
         end if;
         Neg := Pb_Is_Odd (E);
         Mag := -B;
      end if;
      declare
         R : IEEE_Float_64;
      begin
         begin
            R := Pb_EF."**" (Mag, E);
         exception
            when others =>
               R := (if (Mag > 1.0) = (E > 0.0) then Pb_Inf else 0.0);
         end;
         return (if Neg then -R else R);
      end;
   end Pb_Pow_F;

   function Pb_Min_F (A, B : IEEE_Float_64) return IEEE_Float_64 is (if B < A then B else A);
   function Pb_Max_F (A, B : IEEE_Float_64) return IEEE_Float_64 is (if B > A then B else A);

   -- ---- arrays in expressions ---------------------------------------------

   function Pb_Elem (A : Pb_U8_Vectors.Vector; I : Integer_64) return Integer_64 is
     (if I >= 0 and then I < Integer_64 (A.Length) then Pb_I (A.Element (Natural (I))) else 0);

   function Pb_Sum (A : Pb_U8_Vectors.Vector) return Integer_64 is
      S : Integer_64 := 0;
   begin
      for X of A loop
         S := Pb_Add (S, Pb_I (X));
      end loop;
      return S;
   end Pb_Sum;

   function Pb_Product (A : Pb_U8_Vectors.Vector) return Integer_64 is
      S : Integer_64 := 1;
   begin
      for X of A loop
         S := Pb_Mul (S, Pb_I (X));
      end loop;
      return S;
   end Pb_Product;

   function Pb_Elem (A : Pb_I8_Vectors.Vector; I : Integer_64) return Integer_64 is
     (if I >= 0 and then I < Integer_64 (A.Length) then Pb_I (A.Element (Natural (I))) else 0);

   function Pb_Sum (A : Pb_I8_Vectors.Vector) return Integer_64 is
      S : Integer_64 := 0;
   begin
      for X of A loop
         S := Pb_Add (S, Pb_I (X));
      end loop;
      return S;
   end Pb_Sum;

   function Pb_Product (A : Pb_I8_Vectors.Vector) return Integer_64 is
      S : Integer_64 := 1;
   begin
      for X of A loop
         S := Pb_Mul (S, Pb_I (X));
      end loop;
      return S;
   end Pb_Product;

   function Pb_Elem (A : Pb_U16_Vectors.Vector; I : Integer_64) return Integer_64 is
     (if I >= 0 and then I < Integer_64 (A.Length) then Pb_I (A.Element (Natural (I))) else 0);

   function Pb_Sum (A : Pb_U16_Vectors.Vector) return Integer_64 is
      S : Integer_64 := 0;
   begin
      for X of A loop
         S := Pb_Add (S, Pb_I (X));
      end loop;
      return S;
   end Pb_Sum;

   function Pb_Product (A : Pb_U16_Vectors.Vector) return Integer_64 is
      S : Integer_64 := 1;
   begin
      for X of A loop
         S := Pb_Mul (S, Pb_I (X));
      end loop;
      return S;
   end Pb_Product;

   function Pb_Elem (A : Pb_I16_Vectors.Vector; I : Integer_64) return Integer_64 is
     (if I >= 0 and then I < Integer_64 (A.Length) then Pb_I (A.Element (Natural (I))) else 0);

   function Pb_Sum (A : Pb_I16_Vectors.Vector) return Integer_64 is
      S : Integer_64 := 0;
   begin
      for X of A loop
         S := Pb_Add (S, Pb_I (X));
      end loop;
      return S;
   end Pb_Sum;

   function Pb_Product (A : Pb_I16_Vectors.Vector) return Integer_64 is
      S : Integer_64 := 1;
   begin
      for X of A loop
         S := Pb_Mul (S, Pb_I (X));
      end loop;
      return S;
   end Pb_Product;

   function Pb_Elem (A : Pb_U32_Vectors.Vector; I : Integer_64) return Integer_64 is
     (if I >= 0 and then I < Integer_64 (A.Length) then Pb_I (A.Element (Natural (I))) else 0);

   function Pb_Sum (A : Pb_U32_Vectors.Vector) return Integer_64 is
      S : Integer_64 := 0;
   begin
      for X of A loop
         S := Pb_Add (S, Pb_I (X));
      end loop;
      return S;
   end Pb_Sum;

   function Pb_Product (A : Pb_U32_Vectors.Vector) return Integer_64 is
      S : Integer_64 := 1;
   begin
      for X of A loop
         S := Pb_Mul (S, Pb_I (X));
      end loop;
      return S;
   end Pb_Product;

   function Pb_Elem (A : Pb_I32_Vectors.Vector; I : Integer_64) return Integer_64 is
     (if I >= 0 and then I < Integer_64 (A.Length) then Pb_I (A.Element (Natural (I))) else 0);

   function Pb_Sum (A : Pb_I32_Vectors.Vector) return Integer_64 is
      S : Integer_64 := 0;
   begin
      for X of A loop
         S := Pb_Add (S, Pb_I (X));
      end loop;
      return S;
   end Pb_Sum;

   function Pb_Product (A : Pb_I32_Vectors.Vector) return Integer_64 is
      S : Integer_64 := 1;
   begin
      for X of A loop
         S := Pb_Mul (S, Pb_I (X));
      end loop;
      return S;
   end Pb_Product;

   function Pb_Elem (A : Pb_U64_Vectors.Vector; I : Integer_64) return Integer_64 is
     (if I >= 0 and then I < Integer_64 (A.Length) then Pb_I (A.Element (Natural (I))) else 0);

   function Pb_Sum (A : Pb_U64_Vectors.Vector) return Integer_64 is
      S : Integer_64 := 0;
   begin
      for X of A loop
         S := Pb_Add (S, Pb_I (X));
      end loop;
      return S;
   end Pb_Sum;

   function Pb_Product (A : Pb_U64_Vectors.Vector) return Integer_64 is
      S : Integer_64 := 1;
   begin
      for X of A loop
         S := Pb_Mul (S, Pb_I (X));
      end loop;
      return S;
   end Pb_Product;

   function Pb_Elem (A : Pb_I64_Vectors.Vector; I : Integer_64) return Integer_64 is
     (if I >= 0 and then I < Integer_64 (A.Length) then Pb_I (A.Element (Natural (I))) else 0);

   function Pb_Sum (A : Pb_I64_Vectors.Vector) return Integer_64 is
      S : Integer_64 := 0;
   begin
      for X of A loop
         S := Pb_Add (S, Pb_I (X));
      end loop;
      return S;
   end Pb_Sum;

   function Pb_Product (A : Pb_I64_Vectors.Vector) return Integer_64 is
      S : Integer_64 := 1;
   begin
      for X of A loop
         S := Pb_Mul (S, Pb_I (X));
      end loop;
      return S;
   end Pb_Product;

   function Pb_Elem (A : Pb_F32_Vectors.Vector; I : Integer_64) return IEEE_Float_64 is
     (if I >= 0 and then I < Integer_64 (A.Length) then Pb_F (A.Element (Natural (I))) else 0.0);

   function Pb_Sum (A : Pb_F32_Vectors.Vector) return IEEE_Float_64 is
      S : IEEE_Float_64 := 0.0;
   begin
      for X of A loop
         S := S + Pb_F (X);
      end loop;
      return S;
   end Pb_Sum;

   function Pb_Product (A : Pb_F32_Vectors.Vector) return IEEE_Float_64 is
      S : IEEE_Float_64 := 1.0;
   begin
      for X of A loop
         S := S * Pb_F (X);
      end loop;
      return S;
   end Pb_Product;

   function Pb_Elem (A : Pb_F64_Vectors.Vector; I : Integer_64) return IEEE_Float_64 is
     (if I >= 0 and then I < Integer_64 (A.Length) then Pb_F (A.Element (Natural (I))) else 0.0);

   function Pb_Sum (A : Pb_F64_Vectors.Vector) return IEEE_Float_64 is
      S : IEEE_Float_64 := 0.0;
   begin
      for X of A loop
         S := S + Pb_F (X);
      end loop;
      return S;
   end Pb_Sum;

   function Pb_Product (A : Pb_F64_Vectors.Vector) return IEEE_Float_64 is
      S : IEEE_Float_64 := 1.0;
   begin
      for X of A loop
         S := S * Pb_F (X);
      end loop;
      return S;
   end Pb_Product;

   -- ---- trace --------------------------------------------------------------

   function Pb_Path (T : Pb_Trace) return String is
      R : Pb_SU.Unbounded_String;
   begin
      if T.Depth > 0 then
         R := T.Frames (1).Packet;
      end if;
      for I in 1 .. T.Depth loop
         exit when Pb_SU.Length (T.Frames (I).Field) = 0;
         Pb_SU.Append (R, "." & Pb_SU.To_String (T.Frames (I).Field));
         if T.Frames (I).Index >= 0 then
            Pb_SU.Append (R, "[" & Pb_Img (T.Frames (I).Index) & "]");
         end if;
      end loop;
      return Pb_SU.To_String (R);
   end Pb_Path;

   procedure Pb_Fail
     (T : Pb_Trace; Kind : Pb_Error_Kind; Reason : String; Needed : Integer_64 := 0)
     with No_Return;

   procedure Pb_Fail
     (T : Pb_Trace; Kind : Pb_Error_Kind; Reason : String; Needed : Integer_64 := 0) is
   begin
      Pb_Raise (Kind, Reason, Pb_Path (T), T.Pos, Needed);
   end Pb_Fail;

   procedure Pb_Fail
     (R : not null access Pb_Reader; Kind : Pb_Error_Kind; Reason : String; Needed : Integer_64 := 0)
     with No_Return;

   procedure Pb_Fail
     (R : not null access Pb_Reader; Kind : Pb_Error_Kind; Reason : String; Needed : Integer_64 := 0) is
   begin
      Pb_Fail (R.T, Kind, Reason, Needed);
   end Pb_Fail;

   procedure Pb_Fail
     (W : not null access Pb_Writer; Kind : Pb_Error_Kind; Reason : String; Needed : Integer_64 := 0)
     with No_Return;

   procedure Pb_Fail
     (W : not null access Pb_Writer; Kind : Pb_Error_Kind; Reason : String; Needed : Integer_64 := 0) is
   begin
      Pb_Fail (W.T, Kind, Reason, Needed);
   end Pb_Fail;

   procedure Pb_Enter (T : in out Pb_Trace; Packet : String) is
   begin
      if T.Depth >= Pb_Max_Depth + 1 then
         Pb_Fail (T, Pb_Invalid, "packets nested more than" & Natural'Image (Pb_Max_Depth) & " deep");
      end if;
      T.Depth := T.Depth + 1;
      T.Frames (T.Depth) :=
        (Packet => Pb_SU.To_Unbounded_String (Packet), Field => Pb_SU.Null_Unbounded_String, Index => -1);
      if T.Depth > Pb_Max_Depth then
         Pb_Fail (T, Pb_Invalid, "packets nested more than" & Natural'Image (Pb_Max_Depth) & " deep");
      end if;
   end Pb_Enter;

   procedure Pb_Enter (R : not null access Pb_Reader; Packet : String) is
   begin
      Pb_Enter (R.T, Packet);
   end Pb_Enter;

   procedure Pb_Enter (W : not null access Pb_Writer; Packet : String) is
   begin
      Pb_Enter (W.T, Packet);
   end Pb_Enter;

   procedure Pb_Leave (R : not null access Pb_Reader) is
   begin
      if R.T.Depth > 0 then
         R.T.Depth := R.T.Depth - 1;
      end if;
   end Pb_Leave;

   procedure Pb_Leave (W : not null access Pb_Writer) is
   begin
      if W.T.Depth > 0 then
         W.T.Depth := W.T.Depth - 1;
      end if;
   end Pb_Leave;

   procedure Pb_At (T : in out Pb_Trace; Field : String) is
   begin
      if T.Depth > 0 then
         Pb_SU.Set_Unbounded_String (T.Frames (T.Depth).Field, Field);
         T.Frames (T.Depth).Index := -1;
      end if;
   end Pb_At;

   procedure Pb_Field (R : not null access Pb_Reader; Field : String) is
   begin
      Pb_At (R.T, Field);
   end Pb_Field;

   procedure Pb_Field (W : not null access Pb_Writer; Field : String) is
   begin
      Pb_At (W.T, Field);
   end Pb_Field;

   procedure Pb_Index (R : not null access Pb_Reader; I : Integer_64) is
   begin
      if R.T.Depth > 0 then
         R.T.Frames (R.T.Depth).Index := I;
      end if;
   end Pb_Index;

   procedure Pb_Index (W : not null access Pb_Writer; I : Integer_64) is
   begin
      if W.T.Depth > 0 then
         W.T.Frames (W.T.Depth).Index := I;
      end if;
   end Pb_Index;

   function Pb_Pos (R : not null access Pb_Reader) return Integer_64 is (R.T.Pos);
   function Pb_Pos (W : not null access Pb_Writer) return Integer_64 is (W.T.Pos);

   -- @versions{
   --  The protocol version (`version`), or Latest while none is set.
   function Pb_Version_Or (T : Pb_Trace; Latest : Integer_64) return Integer_64 is
     (if T.Version = 0 then Latest else T.Version);

   --  Code as protocol version V, which must be in Min .. Latest.
   procedure Pb_Set_Version (T : in out Pb_Trace; V, Min, Latest : Integer_64) is
   begin
      if V < Min or else V > Latest then
         Pb_Fail (T, Pb_Constraint, "version " & Pb_Img (V) & " is not one of the versions "
           & Pb_Img (Min) & ".." & Pb_Img (Latest));
      end if;
      T.Version := V;
   end Pb_Set_Version;

   --  Take the version a value carries unless the caller gave one.
   procedure Pb_Adopt_Version (T : in out Pb_Trace; V, Min, Latest : Integer_64) is
   begin
      if T.Version = 0 then
         Pb_Set_Version (T, V, Min, Latest);
      end if;
   end Pb_Adopt_Version;

   --  Enter version scope S while at Version: whether a scope was entered
   --  (for Pb_Leave_Scope). A scope entered from another starts without a
   --  version, unless it was left for it earlier.
   procedure Pb_Enter_Scope
     (Sc : in out Pb_Scopes; S : Natural; Version : in out Integer_64; Entered : out Boolean)
   is
      V : Integer_64 := 0;
   begin
      Entered := Sc.Scope /= S + 1;
      if not Entered then
         return;
      end if;
      if Sc.Scope = 0 then
         V := Version;
      else
         for I in reverse 1 .. Sc.Depth loop
            if Sc.Left (I).Scope = S + 1 then
               V := Sc.Left (I).Version;
               exit;
            end if;
         end loop;
      end if;
      if Sc.Depth < Sc.Left'Last then
         Sc.Depth := Sc.Depth + 1;
         Sc.Left (Sc.Depth) := (Scope => Sc.Scope, Version => Version);
      end if;
      Sc.Scope := S + 1;
      Version := V;
   end Pb_Enter_Scope;

   --  Back to the scope Pb_Enter_Scope left, and its version.
   procedure Pb_Leave_Scope (Sc : in out Pb_Scopes; Entered : Boolean; Version : in out Integer_64) is
   begin
      if not Entered then
         return;
      end if;
      if Sc.Depth = 0 then
         Sc.Scope := 0;
         return;
      end if;
      Sc.Scope := Sc.Left (Sc.Depth).Scope;
      Version := Sc.Left (Sc.Depth).Version;
      Sc.Depth := Sc.Depth - 1;
   end Pb_Leave_Scope;

   --  Code a packet of version scope S (`version_scope`).
   function Pb_Enter_Scope (R : not null access Pb_Reader; S : Natural) return Boolean is
      Entered : Boolean;
   begin
      Pb_Enter_Scope (R.Sc, S, R.T.Version, Entered);
      return Entered;
   end Pb_Enter_Scope;

   function Pb_Enter_Scope (W : not null access Pb_Writer; S : Natural) return Boolean is
      Entered : Boolean;
   begin
      Pb_Enter_Scope (W.Sc, S, W.T.Version, Entered);
      return Entered;
   end Pb_Enter_Scope;

   --  After that packet: back to the outer scope and its version.
   procedure Pb_Leave_Scope (R : not null access Pb_Reader; Entered : Boolean) is
   begin
      Pb_Leave_Scope (R.Sc, Entered, R.T.Version);
   end Pb_Leave_Scope;

   procedure Pb_Leave_Scope (W : not null access Pb_Writer; Entered : Boolean) is
   begin
      Pb_Leave_Scope (W.Sc, Entered, W.T.Version);
   end Pb_Leave_Scope;
   -- @versions}

   -- ---- text ---------------------------------------------------------------

   --  The code point of the strict UTF-8 sequence at A (I); I moves past it.
   --  Ok is False (and I is unchanged) for overlong forms, surrogates,
   --  values past U+10FFFF and broken sequences.
   procedure Pb_Utf8_Next
     (A : Pb_Byte_Array; I : in out Natural; Cp : out Unsigned_32; Ok : out Boolean)
   is
      C    : Unsigned_32 := Unsigned_32 (A (I));
      More : Natural;
   begin
      Ok := False;
      Cp := C;
      if C < 16#80# then
         More := 0;
      elsif C >= 16#C2# and then C <= 16#DF# then
         More := 1;
         C := C and 16#1F#;
      elsif C >= 16#E0# and then C <= 16#EF# then
         More := 2;
         C := C and 16#0F#;
      elsif C >= 16#F0# and then C <= 16#F4# then
         More := 3;
         C := C and 16#07#;
      else
         return;
      end if;
      for K in 1 .. More loop
         if I + K > A'Last or else (A (I + K) and 16#C0#) /= 16#80# then
            return;
         end if;
         C := Shift_Left (C, 6) or Unsigned_32 (A (I + K) and 16#3F#);
      end loop;
      if (More = 2 and then (C < 16#800# or else (C >= 16#D800# and then C <= 16#DFFF#)))
        or else (More = 3 and then (C < 16#1_0000# or else C > 16#10_FFFF#))
      then
         return;
      end if;
      Cp := C;
      I := I + More + 1;
      Ok := True;
   end Pb_Utf8_Next;

   procedure Pb_Put_Utf8 (S : in out Pb_SU.Unbounded_String; Cp : Unsigned_32) is
      procedure Put (B : Unsigned_32) is
      begin
         Pb_SU.Append (S, Character'Val (Natural (B and 16#FF#)));
      end Put;
   begin
      if Cp < 16#80# then
         Put (Cp);
      elsif Cp < 16#800# then
         Put (16#C0# or Shift_Right (Cp, 6));
         Put (16#80# or (Cp and 16#3F#));
      elsif Cp < 16#1_0000# then
         Put (16#E0# or Shift_Right (Cp, 12));
         Put (16#80# or (Shift_Right (Cp, 6) and 16#3F#));
         Put (16#80# or (Cp and 16#3F#));
      else
         Put (16#F0# or Shift_Right (Cp, 18));
         Put (16#80# or (Shift_Right (Cp, 12) and 16#3F#));
         Put (16#80# or (Shift_Right (Cp, 6) and 16#3F#));
         Put (16#80# or (Cp and 16#3F#));
      end if;
   end Pb_Put_Utf8;

   function Pb_Valid_Utf8 (A : Pb_Byte_Array) return Boolean is
      I  : Natural := A'First;
      Cp : Unsigned_32;
      Ok : Boolean;
   begin
      while I <= A'Last loop
         Pb_Utf8_Next (A, I, Cp, Ok);
         if not Ok then
            return False;
         end if;
      end loop;
      return True;
   end Pb_Valid_Utf8;

   -- ---- sources ------------------------------------------------------------

   procedure Pb_Free_Source is new Ada.Unchecked_Deallocation (Pb_Byte_Array, Pb_Byte_Array_Access);
   procedure Pb_Free_Source is new Ada.Unchecked_Deallocation (Pb_Flags, Pb_Flags_Access);

   procedure Pb_Open (S : in out Pb_Source'Class; Size : Natural; Page : Positive := 4096) is
   begin
      Pb_Free_Source (S.Buf);
      Pb_Free_Source (S.Loaded);
      S.Size := Size;
      S.Page := Page;
      S.Buf := new Pb_Byte_Array'(0 .. Size - 1 => 0);
      S.Loaded := new Pb_Flags'(0 .. (Size + Page - 1) / Page - 1 => False);
   end Pb_Open;

   overriding procedure Finalize (S : in out Pb_Source) is
   begin
      Pb_Free_Source (S.Buf);
      Pb_Free_Source (S.Loaded);
   end Finalize;

   --  Fetch the pages holding bytes Start .. Start + N - 1 (inside the
   --  input) that are not loaded yet, one Pb_Fetch call per page;
   --  propagates what Pb_Fetch raises.
   procedure Pb_Load_Pages (S : in out Pb_Source'Class; Start, N : Integer_64) is
      Last : constant Integer_64 := Integer_64'Min (Start + N, Integer_64 (S.Size)) - 1;
   begin
      if Start < 0 or else Last < Start then
         return;
      end if;
      for P in Natural (Start / Integer_64 (S.Page)) .. Natural (Last / Integer_64 (S.Page)) loop
         if not S.Loaded (P) then
            declare
               From : constant Natural := P * S.Page;
               Tmp  : Pb_Byte_Array (0 .. Natural'Min (S.Page, S.Size - From) - 1) := (others => 0);
            begin
               S.Pb_Fetch (Integer_64 (From), Tmp);
               S.Buf (From .. From + Tmp'Length - 1) := Tmp;
               S.Loaded (P) := True;
            end;
         end if;
      end loop;
   end Pb_Load_Pages;

   -- ---- reader -------------------------------------------------------------

   procedure Pb_Init (R : in out Pb_Reader; Data : Pb_Byte_Array) is
   begin
      R.Data := Data;
      R.Src := null;
      R.Size := Integer_64 (R.Len);
      R.T := (Frames => <>, Depth => 0, Pos => 0, Version => 0);
      -- @versions{
      R.Sc := (Scope => 0, Left => <>, Depth => 0);
      -- @versions}
      R.Limit := Integer_64 (R.Len) * 8;
      R.Windows := 0;
   end Pb_Init;

   procedure Pb_Init (R : in out Pb_Reader; Src : in out Pb_Source'Class) is
   begin
      R.Src := Src'Unchecked_Access;
      R.Size := Integer_64 (Src.Size);
      R.T := (Frames => <>, Depth => 0, Pos => 0, Version => 0);
      -- @versions{
      R.Sc := (Scope => 0, Left => <>, Depth => 0);
      -- @versions}
      R.Limit := R.Size * 8;
      R.Windows := 0;
   end Pb_Init;

   --  Input bytes Start .. Start + N - 1 (inside the input), loaded from the
   --  source if R has one. A failing fetch is an invalid-input error.
   procedure Pb_Load (R : not null access Pb_Reader; Start, N : Integer_64) is
   begin
      if R.Src /= null then
         Pb_Load_Pages (R.Src.all, Start, N);
      end if;
   exception
      when Pb_Error =>
         Pb_Fail (R, Pb_Invalid, "cannot read the input: " & Pb_SU.To_String (Pb_Last.Reason));
      when E : others =>
         Pb_Fail (R, Pb_Invalid, "cannot read the input: " & Ada.Exceptions.Exception_Message (E));
   end Pb_Load;

   --  Byte I of the input (0 outside it); Pb_Load first for a source.
   function Pb_Byte (R : not null access Pb_Reader; I : Integer_64) return Unsigned_8 is
     (if I < 0 or else I >= R.Size then 0
      elsif R.Src = null then R.Data (Natural (I) + 1)
      else R.Src.Buf (Natural (I)));

   function Pb_Remaining_Bits (R : not null access Pb_Reader) return Integer_64 is (R.Limit - R.T.Pos);
   function Pb_Remaining_Bytes (R : not null access Pb_Reader) return Integer_64 is
     ((R.Limit - R.T.Pos) / 8);

   --  Bits more than the reader has: incomplete at the end of the input,
   --  invalid inside a window.
   procedure Pb_Short (R : not null access Pb_Reader; Bits : Integer_64; What : String) with No_Return;

   procedure Pb_Short (R : not null access Pb_Reader; Bits : Integer_64; What : String) is
      Left : constant Integer_64 := Pb_Remaining_Bits (R);
   begin
      if R.Windows = 0 then
         Pb_Fail (R, Pb_Incomplete, "unexpected end of data: " & What & " needs " & Pb_Img (Bits)
           & " more bit(s), " & Pb_Img (Left) & " left", Bits - Left);
      else
         Pb_Fail (R, Pb_Invalid, What & " needs " & Pb_Img (Bits) & " bit(s) but its window has "
           & Pb_Img (Left) & " left");
      end if;
   end Pb_Short;

   procedure Pb_Need (R : not null access Pb_Reader; Bits : Integer_64) is
   begin
      if Bits < 0 or else Bits > Pb_Remaining_Bits (R) then
         Pb_Short (R, Bits, "the field");
      end if;
   end Pb_Need;

   function Pb_Jump (R : not null access Pb_Reader; From, Offset : Integer_64) return Pb_Jump_State is
      Saved : constant Pb_Jump_State := (Pos => R.T.Pos, Limit => R.Limit, Windows => R.Windows);
      Size  : constant Integer_64 := R.Size;
   begin
      if Offset < 0 or else From < 0 or else From mod 8 /= 0 or else Offset > Size
        or else From > Size * 8 - Offset * 8
      then
         Pb_Fail (R, Pb_Invalid, "offset " & Pb_Img (Offset) & " is past the end of the input");
      end if;
      R.T.Pos := From + Offset * 8;
      R.Limit := Size * 8;
      R.Windows := 0;
      return Saved;
   end Pb_Jump;

   procedure Pb_Jump_Back (R : not null access Pb_Reader; Saved : Pb_Jump_State) is
   begin
      R.T.Pos := Saved.Pos;
      R.Limit := Saved.Limit;
      R.Windows := Saved.Windows;
   end Pb_Jump_Back;

   --  Read only the next N bytes until Pb_Pop_Limit; returns what to restore.
   function Pb_Push_Limit (R : not null access Pb_Reader; N : Integer_64) return Integer_64 is
      Saved : constant Integer_64 := R.Limit;
   begin
      if N < 0 then
         Pb_Fail (R, Pb_Invalid, "negative size " & Pb_Img (N));
      end if;
      if N > Pb_Remaining_Bits (R) / 8 then
         Pb_Short (R, (if N > Integer_64'Last / 8 then Integer_64'Last else N * 8), "the window");
      end if;
      R.Limit := R.T.Pos + N * 8;
      R.Windows := R.Windows + 1;
      return Saved;
   end Pb_Push_Limit;

   procedure Pb_Pop_Limit (R : not null access Pb_Reader; Saved : Integer_64; Exact : Boolean) is
   begin
      if Exact and then Pb_Remaining_Bits (R) > 0 then
         Pb_Fail (R, Pb_Invalid, Pb_Img (Pb_Remaining_Bits (R))
           & " bit(s) left over in a field that must fill its size");
      end if;
      R.T.Pos := R.Limit;
      R.Limit := Saved;
      if R.Windows > 0 then
         R.Windows := R.Windows - 1;
      end if;
   end Pb_Pop_Limit;

   function Pb_Read_Bits (R : not null access Pb_Reader; Width : Natural) return Unsigned_64 is
      Res  : Unsigned_64 := 0;
      Left : Natural := Width;
      Off, Take : Natural;
      B    : Unsigned_64;
   begin
      Pb_Need (R, Integer_64 (Width));
      Pb_Load (R, R.T.Pos / 8, (R.T.Pos + Integer_64 (Width) + 7) / 8 - R.T.Pos / 8);
      while Left > 0 loop
         B := Unsigned_64 (Pb_Byte (R, R.T.Pos / 8));
         Off := Natural (R.T.Pos mod 8);
         Take := Natural'Min (8 - Off, Left);
         Res := Shift_Left (Res, Take) or (Shift_Right (B, 8 - Off - Take) and (Shift_Left (1, Take) - 1));
         R.T.Pos := R.T.Pos + Integer_64 (Take);
         Left := Left - Take;
      end loop;
      return Res;
   end Pb_Read_Bits;

   function Pb_Read_Uint (R : not null access Pb_Reader; N : Natural; Little : Boolean) return Unsigned_64 is
      Res   : Unsigned_64 := 0;
      Start : constant Integer_64 := R.T.Pos / 8;
   begin
      Pb_Need (R, Integer_64 (N) * 8);
      Pb_Load (R, Start, Integer_64 (N));
      for I in 0 .. N - 1 loop
         if Little then
            Res := Shift_Left (Res, 8) or Unsigned_64 (Pb_Byte (R, Start + Integer_64 (N - 1 - I)));
         else
            Res := Shift_Left (Res, 8) or Unsigned_64 (Pb_Byte (R, Start + Integer_64 (I)));
         end if;
      end loop;
      R.T.Pos := R.T.Pos + Integer_64 (N) * 8;
      return Res;
   end Pb_Read_Uint;

   --  Bytes Start .. Stop - 1 of the input (0-based).
   function Pb_Slice (R : not null access Pb_Reader; Start, Stop : Integer_64) return Pb_Byte_Array is
      A : Pb_Byte_Array (0 .. Natural (Integer_64'Max (Stop - Start, 0)) - 1);
   begin
      Pb_Load (R, Start, A'Length);
      for I in A'Range loop
         A (I) := Pb_Byte (R, Start + Integer_64 (I));
      end loop;
      return A;
   end Pb_Slice;

   function Pb_Read_Bytes (R : not null access Pb_Reader; N : Integer_64) return Pb_Byte_Array is
      Start : constant Integer_64 := R.T.Pos / 8;
   begin
      if N < 0 or else N > Pb_Remaining_Bits (R) / 8 then
         Pb_Short (R, (if N < 0 or else N > Integer_64'Last / 8 then Integer_64'Last else N * 8), "the field");
      end if;
      declare
         A : constant Pb_Byte_Array := Pb_Slice (R, Start, Start + N);
      begin
         R.T.Pos := R.T.Pos + N * 8;
         return A;
      end;
   end Pb_Read_Bytes;

   function Pb_Read_Mac (R : not null access Pb_Reader) return Pb_Mac is
      B : constant Pb_Byte_Array := Pb_Read_Bytes (R, 6);
      M : Pb_Mac;
   begin
      for I in M'Range loop
         M (I) := B (B'First + I);
      end loop;
      return M;
   end Pb_Read_Mac;

   procedure Pb_Skip_Bits (R : not null access Pb_Reader; Bits : Integer_64) is
   begin
      Pb_Need (R, Bits);
      R.T.Pos := R.T.Pos + Bits;
   end Pb_Skip_Bits;

   --  Where Term first starts in input bytes Start .. Stop - 1, or -1. A
   --  source is scanned page by page, so it is only read up to Term.
   function Pb_Find (R : not null access Pb_Reader; Start, Stop : Integer_64; Term : Pb_Byte_Array)
      return Integer_64
   is
      Len  : constant Integer_64 := Integer_64 (Term'Length);
      From : Integer_64 := Start;
      To   : Integer_64 := Stop;
      I    : Integer_64;
      Hit  : Boolean;
   begin
      while From < Stop loop
         if R.Src /= null then
            To := Integer_64'Min ((From / Integer_64 (R.Src.Page) + 1) * Integer_64 (R.Src.Page) + Len - 1, Stop);
            Pb_Load (R, From, To - From);
         end if;
         I := From;
         while I + Len <= To loop
            Hit := True;
            for K in Term'Range loop
               if Pb_Byte (R, I + Integer_64 (K - Term'First)) /= Term (K) then
                  Hit := False;
                  exit;
               end if;
            end loop;
            if Hit then
               return I;
            end if;
            I := I + 1;
         end loop;
         exit when To = Stop;
         From := To + 1 - Len;
      end loop;
      return -1;
   end Pb_Find;

   function Pb_Read_CString (R : not null access Pb_Reader) return Pb_Byte_Array is
      Start : constant Integer_64 := R.T.Pos / 8;
      Stop  : constant Integer_64 := R.Limit / 8;
      I     : constant Integer_64 := Pb_Find (R, Start, Stop, (0 => 0));
   begin
      if I < 0 then
         Pb_Short (R, Pb_Remaining_Bits (R) + 8, "the NUL-terminated string");
      end if;
      R.T.Pos := (I + 1) * 8;
      return Pb_Slice (R, Start, I);
   end Pb_Read_CString;

   function Pb_Read_Until
     (R : not null access Pb_Reader; Term : Pb_Byte_Array; Optional : Boolean) return Pb_Byte_Array
   is
      Start : constant Integer_64 := R.T.Pos / 8;
      Stop  : constant Integer_64 := R.Limit / 8;
      I     : constant Integer_64 := Pb_Find (R, Start, Stop, Term);
   begin
      if I >= 0 then
         declare
            A : constant Pb_Byte_Array := Pb_Slice (R, Start, I);
         begin
            R.T.Pos := (I + Integer_64 (Term'Length)) * 8;
            return A;
         end;
      end if;
      if not Optional then
         Pb_Short (R, Pb_Remaining_Bits (R) + 8, "the terminated field");
      end if;
      declare
         A : constant Pb_Byte_Array := Pb_Slice (R, Start, Stop);
      begin
         R.T.Pos := R.Limit;
         return A;
      end;
   end Pb_Read_Until;

   --  A length N of ElemBits-bit elements, checked against what is left.
   function Pb_Count (R : not null access Pb_Reader; N, Elem_Bits : Integer_64) return Integer_64 is
   begin
      if N < 0 then
         Pb_Fail (R, Pb_Invalid, "negative length " & Pb_Img (N));
      end if;
      if Elem_Bits > 0 and then N > Pb_Remaining_Bits (R) / Elem_Bits then
         Pb_Short (R, (if N > Integer_64'Last / Elem_Bits then Integer_64'Last else N * Elem_Bits),
           "length " & Pb_Img (N));
      end if;
      return N;
   end Pb_Count;

   --  Strict UTF-8 kept as it is (up to the first NUL when Until_Nul).
   function Pb_Decode_Utf8
     (R : not null access Pb_Reader; Raw : Pb_Byte_Array; Until_Nul : Boolean) return Pb_SU.Unbounded_String
   is
      Last : Integer := Raw'Last;
   begin
      if Until_Nul then
         for I in Raw'Range loop
            if Raw (I) = 0 then
               Last := I - 1;
               exit;
            end if;
         end loop;
      end if;
      if not Pb_Valid_Utf8 (Raw (Raw'First .. Last)) then
         Pb_Fail (R, Pb_Text, "invalid UTF-8");
      end if;
      return Pb_SU.To_Unbounded_String (Pb_Bytes_Str (Raw (Raw'First .. Last)));
   end Pb_Decode_Utf8;

   --  Text in encoding Enc (0 UTF-8, 1 ASCII, 2 Latin-1, 3 UTF-16LE,
   --  4 UTF-16BE) as UTF-8; Padded: up to the first NUL.
   function Pb_Decode_Text
     (R : not null access Pb_Reader; Raw : Pb_Byte_Array; Enc : Natural; Padded : Boolean)
      return Pb_SU.Unbounded_String
   is
      Units : constant Natural := (if Enc >= 3 then 2 else 1);
      N     : Natural := Raw'Length;
      S     : Pb_SU.Unbounded_String;
      C, D  : Unsigned_32;
      I     : Natural := 0;

      function Unit (K : Natural) return Unsigned_32 is
        (if Enc = 3 then Unsigned_32 (Raw (Raw'First + 2 * K)) or Shift_Left (Unsigned_32 (Raw (Raw'First + 2 * K + 1)), 8)
         elsif Enc = 4 then Shift_Left (Unsigned_32 (Raw (Raw'First + 2 * K)), 8) or Unsigned_32 (Raw (Raw'First + 2 * K + 1))
         else Unsigned_32 (Raw (Raw'First + K)));
   begin
      if Enc = 0 then
         return Pb_Decode_Utf8 (R, Raw, Padded);
      end if;
      if N mod Units /= 0 then
         Pb_Fail (R, Pb_Text, "invalid UTF-16 (an odd number of bytes)");
      end if;
      if Padded then
         for K in 0 .. N / Units - 1 loop
            if Unit (K) = 0 then
               N := K * Units;
               exit;
            end if;
         end loop;
      end if;
      while I < N / Units loop
         C := Unit (I);
         I := I + 1;
         if Enc = 1 and then C > 16#7F# then
            Pb_Fail (R, Pb_Text, "invalid ASCII");
         end if;
         if Enc >= 3 and then C >= 16#D800# and then C <= 16#DFFF# then
            --  Surrogates come in pairs: a high one, then a low one.
            if C > 16#DBFF# or else I >= N / Units then
               Pb_Fail (R, Pb_Text, "invalid UTF-16");
            end if;
            D := Unit (I);
            if D < 16#DC00# or else D > 16#DFFF# then
               Pb_Fail (R, Pb_Text, "invalid UTF-16");
            end if;
            I := I + 1;
            C := 16#1_0000# + Shift_Left (C - 16#D800#, 10) + (D - 16#DC00#);
         end if;
         Pb_Put_Utf8 (S, C);
      end loop;
      return S;
   end Pb_Decode_Text;

   --  Kind: 0 uleb128, 1 sleb128, 2 zigzag, 3 vlq, 4 quic, 5 varint15.
   function Pb_Read_Varint (R : not null access Pb_Reader; Kind : Natural) return Unsigned_64 is
      First, B, Q : Unsigned_64;
      Res     : Unsigned_64 := 0;
      N       : Natural;
      Shift   : Natural := 0;
      Last_Ok : Boolean;
   begin
      if Kind = 5 then
         First := Pb_Read_Uint (R, 1, False);
         if (First and 16#80#) = 0 then
            return First;
         end if;
         return Shift_Left (First and 16#7F#, 8) or Pb_Read_Uint (R, 1, False);
      end if;
      if Kind = 4 then
         First := Pb_Read_Uint (R, 1, False);
         N := 2 ** Natural (Shift_Right (First, 6));
         Q := First and 16#3F#;
         if N > 1 then
            Q := Shift_Left (Q, 8 * (N - 1)) or Pb_Read_Uint (R, N - 1, False);
         end if;
         return Q;
      end if;
      loop
         B := Pb_Read_Uint (R, 1, False);
         if Kind = 3 then
            if Shift_Right (Res, 57) /= 0 then
               Pb_Fail (R, Pb_Invalid, "the varint does not fit in 64 bits");
            end if;
            Res := Shift_Left (Res, 7) or (B and 16#7F#);
         else
            --  The 10th byte holds bit 63 only (and, for sleb128, its sign).
            if Kind = 1 then
               Last_Ok := (B and 16#7F#) = 0 or else (B and 16#7F#) = 16#7F#;
            else
               Last_Ok := (B and 16#7E#) = 0;
            end if;
            if Shift >= 64 or else (Shift = 63 and then ((B and 16#80#) /= 0 or else not Last_Ok)) then
               Pb_Fail (R, Pb_Invalid, "the varint does not fit in 64 bits");
            end if;
            Res := Res or Shift_Left (B and 16#7F#, Shift);
         end if;
         Shift := Natural'Min (Shift + 7, 70);
         if (B and 16#80#) = 0 then
            if Kind = 1 and then Shift < 64 and then (B and 16#40#) /= 0 then
               Res := Res or Shift_Left (Unsigned_64'Last, Shift);
            end if;
            exit;
         end if;
      end loop;
      if Kind = 2 then
         Res := Shift_Right (Res, 1) xor (0 - (Res and 1));
      end if;
      return Res;
   end Pb_Read_Varint;

   -- ---- checksums ----------------------------------------------------------

   type Pb_Crc is record
      Width     : Natural;
      Poly      : Unsigned_64;
      Init      : Unsigned_64;
      Reflected : Boolean;
      Xor_Out   : Unsigned_64;
   end record;

   --  CRC parameters by algorithm number: width, polynomial (reflected for
   --  reflected CRCs), initial value, reflected, final XOR.
   Pb_Crcs : constant array (0 .. 7) of Pb_Crc :=
     ((8, 16#07#, 0, False, 0),                                    --  crc8 (CRC-8/SMBUS)
      (16, 16#A001#, 0, True, 0),                                  --  crc16_arc
      (16, 16#1021#, 16#FFFF#, False, 0),                          --  crc16_ccitt_false
      (16, 16#1021#, 0, False, 0),                                 --  crc16_xmodem
      (16, 16#8408#, 0, True, 0),                                  --  crc16_kermit
      (16, 16#A001#, 16#FFFF#, True, 0),                           --  crc16_modbus
      (32, 16#EDB8_8320#, 16#FFFF_FFFF#, True, 16#FFFF_FFFF#),     --  crc32
      (32, 16#82F6_3B78#, 16#FFFF_FFFF#, True, 16#FFFF_FFFF#));    --  crc32c

   --  The checksum of bytes From .. To - 1 of Buf (0-based); bytes in
   --  Hole_From .. Hole_To - 1 count as zero.
   function Pb_Checksum_Of
     (Algo : Natural; Buf : Pb_Byte_Array; From, To, Hole_From, Hole_To : Integer_64) return Unsigned_64
   is
      X, A, B, Mask, Crc : Unsigned_64 := 0;
      P : Pb_Crc;
      I : Integer_64 := From;
   begin
      if Algo < 8 then
         P := Pb_Crcs (Algo);
         Mask := Shift_Left (1, P.Width) - 1;
         Crc := P.Init;
      end if;
      while I < To loop
         if (I >= Hole_From and then I < Hole_To) or else I < 0 or else I >= Integer_64 (Buf'Length) then
            X := 0;
         else
            X := Unsigned_64 (Buf (Buf'First + Natural (I)));
         end if;
         if Algo < 8 then
            if P.Reflected then
               Crc := Crc xor X;
               for K in 1 .. 8 loop
                  if (Crc and 1) /= 0 then
                     Crc := Shift_Right (Crc, 1) xor P.Poly;
                  else
                     Crc := Shift_Right (Crc, 1);
                  end if;
               end loop;
            else
               Crc := Crc xor Shift_Left (X, P.Width - 8);
               for K in 1 .. 8 loop
                  if (Crc and Shift_Left (1, P.Width - 1)) /= 0 then
                     Crc := (Shift_Left (Crc, 1) xor P.Poly) and Mask;
                  else
                     Crc := Shift_Left (Crc, 1) and Mask;
                  end if;
               end loop;
            end if;
         else
            case Algo is
               when 8 =>
                  if (I - From) mod 2 = 0 then
                     A := A + Shift_Left (X, 8);
                  else
                     A := A + X;
                  end if;
               when 9 =>
                  A := (A + X) mod 255;
                  B := (B + A) mod 255;
               when 10 =>
                  A := (A + X) and 16#FF#;
               when 12 =>
                  A := (A + X) and 16#FFFF#;
               when 13 =>
                  A := (A + Shift_Left (X, 8 * Natural (3 - (I - From) mod 4))) and 16#FFFF_FFFF#;
               when others =>
                  A := A xor X;
            end case;
         end if;
         I := I + 1;
      end loop;
      if Algo < 8 then
         return (Crc xor P.Xor_Out) and Mask;
      elsif Algo = 8 then
         while Shift_Right (A, 16) /= 0 loop
            A := (A and 16#FFFF#) + Shift_Right (A, 16);
         end loop;
         return (not A) and 16#FFFF#;
      elsif Algo = 13 then
         return (Shift_Right (A, 16) + (A and 16#FFFF#)) and 16#FFFF#;
      elsif Algo = 9 then
         return Shift_Left (B, 8) or A;
      end if;
      return A;
   end Pb_Checksum_Of;

   --  From a source that cannot be read, the checksum of zeros (which then
   --  fails to match).
   function Pb_Checksum
     (R : not null access Pb_Reader; Algo : Natural; From, To, Hole_From, Hole_To : Integer_64)
      return Unsigned_64
   is
      Base : constant Integer_64 := From / 8;
      N    : constant Integer_64 := Integer_64'Max (To / 8 - Base, 0);
   begin
      if R.Src = null then
         return Pb_Checksum_Of (Algo, R.Data, From / 8, To / 8, Hole_From / 8, Hole_To / 8);
      end if;
      begin
         Pb_Load_Pages (R.Src.all, Base, N);
      exception
         when others =>
            declare
               Zeros : constant Pb_Byte_Array (0 .. Natural (N) - 1) := (others => 0);
            begin
               return Pb_Checksum_Of (Algo, Zeros, 0, N, Integer_64'Max (Hole_From / 8 - Base, 0),
                 Integer_64'Max (Hole_To / 8 - Base, 0));
            end;
      end;
      return Pb_Checksum_Of (Algo, R.Src.Buf.all, From / 8, To / 8, Hole_From / 8, Hole_To / 8);
   end Pb_Checksum;

   -- ---- writer -------------------------------------------------------------

   function Pb_Checksum
     (W : not null access Pb_Writer; Algo : Natural; From, To, Hole_From, Hole_To : Integer_64)
      return Unsigned_64 is
     (Pb_Checksum_Of (Algo, Pb_Arr (W.Buf), From / 8, To / 8, Hole_From / 8, Hole_To / 8));

   --  A writer for an `at` field: Offset bytes from bit From of W (or from
   --  the start of the output when Root).
   procedure Pb_Sub
     (W : not null access Pb_Writer; From, Offset : Integer_64; Root : Boolean; S : not null access Pb_Writer)
   is
      Start : constant Integer_64 := (if Root then 0 else Pb_Add (W.Base, From));
   begin
      if Offset < 0 or else Start mod 8 /= 0 then
         Pb_Fail (W, Pb_Range, "bad offset " & Pb_Img (Offset) & " (from bit " & Pb_Img (Start) & ")");
      end if;
      S.Base := Pb_Add (Start, Pb_Mul (Offset, 8));
      S.T.Frames := W.T.Frames;
      S.T.Depth := W.T.Depth;
      S.T.Version := W.T.Version;
      -- @versions{
      S.Sc := W.Sc;
      -- @versions}
   end Pb_Sub;

   --  Keep what sub-writer S wrote, to be placed by Pb_Finish.
   procedure Pb_Place (W : not null access Pb_Writer; S : not null access Pb_Writer) is
   begin
      W.Placed.Append
        ((At_Byte => S.Base / 8, Data => S.Buf, Path => Pb_SU.To_Unbounded_String (Pb_Path (W.T))));
      for X of S.Placed loop
         W.Placed.Append (X);
      end loop;
   end Pb_Place;

   procedure Pb_Add_Byte (W : not null access Pb_Writer; B : Unsigned_8) is
   begin
      W.Buf.Append (B);
   end Pb_Add_Byte;

   --  The output, with the placed packets written at their offsets.
   function Pb_Finish (W : not null access Pb_Writer) return Pb_Byte_Array is
      T : Pb_Placed;
      J : Integer;
      K : Integer_64;
   begin
      --  Insertion sort by offset, stable like the other runtimes.
      for I in 1 .. Integer (W.Placed.Length) - 1 loop
         T := W.Placed.Element (I);
         J := I - 1;
         while J >= 0 and then W.Placed.Element (J).At_Byte > T.At_Byte loop
            W.Placed.Replace_Element (J + 1, W.Placed.Element (J));
            J := J - 1;
         end loop;
         W.Placed.Replace_Element (J + 1, T);
      end loop;
      for P of W.Placed loop
         --  The output reaches the offset even when the packet is empty.
         while Integer_64 (W.Buf.Length) < P.At_Byte loop
            Pb_Add_Byte (W, 0);
         end loop;
         for D in 0 .. Integer (P.Data.Length) - 1 loop
            K := P.At_Byte + Integer_64 (D);
            if K < Integer_64 (W.Buf.Length) then
               if K < 0 or else W.Buf.Element (Natural (K)) /= P.Data.Element (D) then
                  Pb_Raise (Pb_Mismatch, "the packet placed at byte " & Pb_Img (P.At_Byte)
                    & " does not match the bytes already there", Pb_SU.To_String (P.Path), Pb_Mul (K, 8));
               end if;
            else
               Pb_Add_Byte (W, P.Data.Element (D));
            end if;
         end loop;
      end loop;
      W.Placed.Clear;
      return Pb_Arr (W.Buf);
   end Pb_Finish;

   procedure Pb_Write_Bits (W : not null access Pb_Writer; V : Unsigned_64; Width : Natural) is
      Left : Natural := Width;
      Off, Take : Natural;
      Bits : Unsigned_64;
      Last : Natural;
   begin
      while Left > 0 loop
         if W.T.Pos mod 8 = 0 then
            Pb_Add_Byte (W, 0);
         end if;
         Off := Natural (W.T.Pos mod 8);
         Take := Natural'Min (8 - Off, Left);
         Bits := Shift_Right (V, Left - Take) and (Shift_Left (1, Take) - 1);
         Last := W.Buf.Last_Index;
         W.Buf.Replace_Element (Last, W.Buf.Element (Last) or Unsigned_8 (Shift_Left (Bits, 8 - Off - Take) and 16#FF#));
         W.T.Pos := W.T.Pos + Integer_64 (Take);
         Left := Left - Take;
      end loop;
   end Pb_Write_Bits;

   procedure Pb_Write_Uint (W : not null access Pb_Writer; V : Unsigned_64; N : Natural; Little : Boolean) is
      Shift : Natural;
   begin
      for I in 0 .. N - 1 loop
         Shift := (if Little then 8 * I else 8 * (N - 1 - I));
         Pb_Add_Byte (W, Unsigned_8 (Shift_Right (V, Shift) and 16#FF#));
      end loop;
      W.T.Pos := W.T.Pos + Integer_64 (N) * 8;
   end Pb_Write_Uint;

   procedure Pb_Write_Bytes (W : not null access Pb_Writer; B : Pb_Byte_Array) is
   begin
      for X of B loop
         Pb_Add_Byte (W, X);
      end loop;
      W.T.Pos := W.T.Pos + Integer_64 (B'Length) * 8;
   end Pb_Write_Bytes;

   procedure Pb_Write_Bytes (W : not null access Pb_Writer; B : Pb_Bytes) is
   begin
      for X of B loop
         Pb_Add_Byte (W, X);
      end loop;
      W.T.Pos := W.T.Pos + Integer_64 (B.Length) * 8;
   end Pb_Write_Bytes;

   procedure Pb_Write_Mac (W : not null access Pb_Writer; M : Pb_Mac) is
   begin
      for X of M loop
         Pb_Add_Byte (W, X);
      end loop;
      W.T.Pos := W.T.Pos + 48;
   end Pb_Write_Mac;

   procedure Pb_Write_Zero_Bits (W : not null access Pb_Writer; Bits : Integer_64) is
      Left : Integer_64 := Bits;
   begin
      while Left > 32 loop
         Pb_Write_Bits (W, 0, 32);
         Left := Left - 32;
      end loop;
      if Left > 0 then
         Pb_Write_Bits (W, 0, Natural (Left));
      end if;
   end Pb_Write_Zero_Bits;

   --  End a window of Size bytes that started at bit Start: check, then pad.
   procedure Pb_End_Window (W : not null access Pb_Writer; Start, Size : Integer_64; Exact : Boolean) is
      Used : constant Integer_64 := W.T.Pos - Start;
   begin
      if Size < 0 or else (Size <= Integer_64'Last / 8 and then Used > Size * 8) then
         Pb_Fail (W, Pb_Range, "the content takes " & Pb_Img (Used) & " bit(s), more than its size of "
           & Pb_Img (Size) & " byte(s)");
      end if;
      if Exact and then (Size > Integer_64'Last / 8 or else Used /= Size * 8) then
         Pb_Fail (W, Pb_Mismatch, "the content takes " & Pb_Img (Used) & " bit(s) but must fill its "
           & Pb_Img (Size) & " byte(s)");
      end if;
      Pb_Write_Zero_Bits (W, (if Size > Integer_64'Last / 8 then Integer_64'Last else Size * 8) - Used);
   end Pb_End_Window;

   procedure Pb_Set_Byte (W : not null access Pb_Writer; I : Integer_64; B : Unsigned_8) is
   begin
      if I >= 0 and then I < Integer_64 (W.Buf.Length) then
         W.Buf.Replace_Element (Natural (I), B);
      end if;
   end Pb_Set_Byte;

   function Pb_Get_Byte (W : not null access Pb_Writer; I : Integer_64) return Unsigned_8 is
     (if I >= 0 and then I < Integer_64 (W.Buf.Length) then W.Buf.Element (Natural (I)) else 0);

   procedure Pb_Patch_Uint
     (W : not null access Pb_Writer; At_Bit : Integer_64; V : Unsigned_64; N : Natural; Little : Boolean)
   is
      Shift : Natural;
   begin
      for I in 0 .. N - 1 loop
         Shift := (if Little then 8 * I else 8 * (N - 1 - I));
         Pb_Set_Byte (W, At_Bit / 8 + Integer_64 (I), Unsigned_8 (Shift_Right (V, Shift) and 16#FF#));
      end loop;
   end Pb_Patch_Uint;

   procedure Pb_Patch_Bits (W : not null access Pb_Writer; At_Bit : Integer_64; V : Unsigned_64; Width : Natural) is
      Bit : Unsigned_8;
      B   : Integer_64;
      Off : Natural;
   begin
      for I in 0 .. Width - 1 loop
         Bit := Unsigned_8 (Shift_Right (V, Width - 1 - I) and 1);
         B := (At_Bit + Integer_64 (I)) / 8;
         Off := 7 - Natural ((At_Bit + Integer_64 (I)) mod 8);
         Pb_Set_Byte (W, B, (Pb_Get_Byte (W, B) and not Shift_Left (1, Off)) or Shift_Left (Bit, Off));
      end loop;
   end Pb_Patch_Bits;

   function Pb_Utf8_Bytes (W : not null access Pb_Writer; S : Pb_SU.Unbounded_String) return Pb_Bytes is
      A : constant Pb_Byte_Array := Pb_Str_Bytes (Pb_SU.To_String (S));
   begin
      if not Pb_Valid_Utf8 (A) then
         Pb_Fail (W, Pb_Text, "the string is not valid UTF-8");
      end if;
      return Pb_Vec (A);
   end Pb_Utf8_Bytes;

   --  The UTF-8 text S in encoding Enc (see Pb_Decode_Text).
   function Pb_Text_Bytes (W : not null access Pb_Writer; S : Pb_SU.Unbounded_String; Enc : Natural) return Pb_Bytes is
      A   : constant Pb_Byte_Array := Pb_Str_Bytes (Pb_SU.To_String (S));
      V   : Pb_Bytes;
      I   : Natural := A'First;
      Cp  : Unsigned_32;
      Ok  : Boolean;
      Name : constant String :=
        (case Enc is when 1 => "ASCII", when 2 => "Latin-1", when others => "UTF-16");

      procedure Unit (U : Unsigned_32) is
      begin
         if Enc = 3 then
            V.Append (Unsigned_8 (U and 16#FF#));
            V.Append (Unsigned_8 (Shift_Right (U, 8) and 16#FF#));
         else
            V.Append (Unsigned_8 (Shift_Right (U, 8) and 16#FF#));
            V.Append (Unsigned_8 (U and 16#FF#));
         end if;
      end Unit;
   begin
      if Enc = 0 then
         return Pb_Utf8_Bytes (W, S);
      end if;
      while I <= A'Last loop
         Pb_Utf8_Next (A, I, Cp, Ok);
         if not Ok or else (Enc = 1 and then Cp > 16#7F#) or else (Enc = 2 and then Cp > 16#FF#) then
            Pb_Fail (W, Pb_Text, "the string is not valid " & Name);
         end if;
         if Enc >= 3 then
            if Cp >= 16#1_0000# then
               Unit (16#D800# + Shift_Right (Cp - 16#1_0000#, 10));
               Unit (16#DC00# + ((Cp - 16#1_0000#) and 16#3FF#));
            else
               Unit (Cp);
            end if;
         else
            V.Append (Unsigned_8 (Cp));
         end if;
      end loop;
      return V;
   end Pb_Text_Bytes;

   procedure Pb_Write_Varint (W : not null access Pb_Writer; Kind : Natural; V : Unsigned_64) is
      U      : Unsigned_64 := V;
      X      : Integer_64;
      B      : Unsigned_64;
      Done   : Boolean;
      Groups : array (0 .. 9) of Unsigned_64 := (others => 0);
      N      : Natural;
   begin
      case Kind is
         when 5 =>
            if U < 16#80# then
               Pb_Write_Uint (W, U, 1, False);
            elsif U <= 16#7FFF# then
               Pb_Write_Uint (W, U or 16#8000#, 2, False);
            else
               Pb_Fail (W, Pb_Range, Pb_Img_U (U) & " does not fit in a varint15");
            end if;
         when 4 =>
            if U <= 16#3F# then
               Pb_Write_Uint (W, U, 1, False);
            elsif U <= 16#3FFF# then
               Pb_Write_Uint (W, U or Shift_Left (1, 14), 2, False);
            elsif U <= 16#3FFF_FFFF# then
               Pb_Write_Uint (W, U or Shift_Left (2, 30), 4, False);
            elsif U <= 16#3FFF_FFFF_FFFF_FFFF# then
               Pb_Write_Uint (W, U or Shift_Left (3, 62), 8, False);
            else
               Pb_Fail (W, Pb_Range, Pb_Img_U (U) & " does not fit in a QUIC varint");
            end if;
         when 1 =>
            X := Pb_U2I (U);
            loop
               B := Pb_I2U (X) and 16#7F#;
               X := Pb_Shr (X, 7);
               Done := (X = 0 and then (B and 16#40#) = 0) or else (X = -1 and then (B and 16#40#) /= 0);
               Pb_Write_Uint (W, (if Done then B else B or 16#80#), 1, False);
               exit when Done;
            end loop;
         when 3 =>
            Groups (0) := U and 16#7F#;
            N := 1;
            U := Shift_Right (U, 7);
            while U /= 0 loop
               Groups (N) := (U and 16#7F#) or 16#80#;
               N := N + 1;
               U := Shift_Right (U, 7);
            end loop;
            for I in reverse 0 .. N - 1 loop
               Pb_Write_Uint (W, Groups (I), 1, False);
            end loop;
         when others =>
            if Kind = 2 then
               U := Shift_Left (U, 1) xor Pb_I2U (Pb_Shr (Pb_U2I (U), 63));
            end if;
            loop
               B := U and 16#7F#;
               U := Shift_Right (U, 7);
               Pb_Write_Uint (W, (if U /= 0 then B or 16#80# else B), 1, False);
               exit when U = 0;
            end loop;
      end case;
   end Pb_Write_Varint;

   procedure Pb_Check_No_Term (W : not null access Pb_Writer; Data, Term : Pb_Byte_Array) is
      I   : Integer := Data'First;
      Hit : Boolean;
   begin
      while I + Term'Length - 1 <= Data'Last loop
         Hit := True;
         for K in Term'Range loop
            if Data (I + (K - Term'First)) /= Term (K) then
               Hit := False;
               exit;
            end if;
         end loop;
         if Hit then
            Pb_Fail (W, Pb_Invalid, "the value contains its terminator");
         end if;
         I := I + 1;
      end loop;
   end Pb_Check_No_Term;

   procedure Pb_Check_Fits (W : not null access Pb_Writer; Length, Size : Integer_64) is
   begin
      if Length > Size then
         Pb_Fail (W, Pb_Range, Pb_Img (Length) & " byte(s) do not fit in " & Pb_Img (Size));
      end if;
   end Pb_Check_Fits;

   procedure Pb_Check_No_Nul (W : not null access Pb_Writer; Data : Pb_Byte_Array) is
   begin
      for X of Data loop
         if X = 0 then
            Pb_Fail (W, Pb_Text, "the string contains a NUL byte");
         end if;
      end loop;
   end Pb_Check_No_Nul;

   procedure Pb_Check_Len (W : not null access Pb_Writer; Actual, Expected : Integer_64) is
   begin
      if Actual /= Expected then
         Pb_Fail (W, Pb_Mismatch, Pb_Img (Actual) & " element(s) but the length expression says "
           & Pb_Img (Expected));
      end if;
   end Pb_Check_Len;

   procedure Pb_Check_U (W : not null access Pb_Writer; V : Unsigned_64; Width : Natural) is
   begin
      if Width < 64 and then Shift_Right (V, Width) /= 0 then
         Pb_Fail (W, Pb_Range, "value " & Pb_Img_U (V) & " does not fit in" & Natural'Image (Width) & " bit(s)");
      end if;
   end Pb_Check_U;

   procedure Pb_Check_I (W : not null access Pb_Writer; V : Integer_64; Width : Natural) is
      Half : Integer_64;
   begin
      if Width > 0 and then Width < 64 then
         Half := Pb_U2I (Shift_Left (1, Width - 1));
         if V < -Half or else V > Half - 1 then
            Pb_Fail (W, Pb_Range, "value " & Pb_Img (V) & " does not fit in" & Natural'Image (Width)
              & " signed bit(s)");
         end if;
      end if;
   end Pb_Check_I;

   -- ---- JSON ---------------------------------------------------------------

   Pb_Hex_Digits : constant String := "0123456789abcdef";

   function Pb_Json_Hex (B : Pb_Byte_Array) return String is
      S : String (1 .. 2 * B'Length + 2);
   begin
      S (1) := '"';
      for I in 0 .. B'Length - 1 loop
         S (2 * I + 2) := Pb_Hex_Digits (Natural (Shift_Right (B (B'First + I), 4)) + 1);
         S (2 * I + 3) := Pb_Hex_Digits (Natural (B (B'First + I) and 15) + 1);
      end loop;
      S (S'Last) := '"';
      return S;
   end Pb_Json_Hex;

   function Pb_Json_Hex (B : Pb_Bytes) return String is (Pb_Json_Hex (Pb_Arr (B)));

   function Pb_Json_Mac (M : Pb_Mac) return String is (Pb_Json_Hex (Pb_Byte_Array (M)));

   function Pb_Json_Str (S : String) return String is
      A  : constant Pb_Byte_Array := Pb_Str_Bytes (S);
      R  : Pb_SU.Unbounded_String;
      I  : Natural := A'First;
      Cp : Unsigned_32;
      Ok : Boolean;

      procedure Esc (U : Unsigned_32) is
      begin
         Pb_SU.Append (R, "\u");
         for K in reverse 0 .. 3 loop
            Pb_SU.Append (R, Pb_Hex_Digits (Natural (Shift_Right (U, 4 * K) and 15) + 1));
         end loop;
      end Esc;
   begin
      Pb_SU.Append (R, '"');
      while I <= A'Last loop
         Pb_Utf8_Next (A, I, Cp, Ok);
         if not Ok then
            Esc (Unsigned_32 (A (I)));
            I := I + 1;
         elsif Cp = Character'Pos ('"') then
            Pb_SU.Append (R, "\""");
         elsif Cp = Character'Pos ('\') then
            Pb_SU.Append (R, "\\");
         elsif Cp >= 16#1_0000# then
            Esc (16#D800# + Shift_Right (Cp - 16#1_0000#, 10));
            Esc (16#DC00# + ((Cp - 16#1_0000#) and 16#3FF#));
         elsif Cp < 16#20# or else Cp > 16#7E# then
            Esc (Cp);
         else
            Pb_SU.Append (R, Character'Val (Natural (Cp)));
         end if;
      end loop;
      Pb_SU.Append (R, '"');
      return Pb_SU.To_String (R);
   end Pb_Json_Str;

   function Pb_Json_Str (S : Pb_SU.Unbounded_String) return String is (Pb_Json_Str (Pb_SU.To_String (S)));

   function Pb_Json_I (V : Integer_64) return String is (Pb_Img (V));

   function Pb_Json_U (V : Unsigned_64) return String is (Pb_Img_U (V));

   --  17 significant digits; null for NaN and infinities.
   function Pb_Json_F (V : IEEE_Float_64) return String is
      S : String (1 .. 40);
      F : Natural := S'First;
   begin
      if not Pb_Is_Finite (V) then
         return "null";
      end if;
      Pb_FIO.Put (To => S, Item => V, Aft => 16, Exp => 3);
      while S (F) = ' ' loop
         F := F + 1;
      end loop;
      return S (F .. S'Last);
   end Pb_Json_F;

   -- ---- generated packets --------------------------------------------------
