"""
 Most object types in the V8 JavaScript are described in this file.

 Inheritance hierarchy:
 - Object
   - Smi          (immediate small integer)
   - HeapObject   (superclass for everything allocated in the heap)
     - JSReceiver  (suitable for property access)
       - JSObject
         - JSArray
         - JSArrayBuffer
         - JSArrayBufferView
           - JSTypedArray
           - JSDataView
         - JSCollection
           - JSSet
           - JSMap
         - JSSetIterator
         - JSMapIterator
         - JSWeakCollection
           - JSWeakMap
           - JSWeakSet
         - JSRegExp
         - JSFunction
         - JSGeneratorObject
         - JSModule
         - JSGlobalObject
         - JSGlobalProxy
         - JSValue
           - JSDate
         - JSMessageObject
       - JSProxy
         - JSFunctionProxy
     - FixedArrayBase
       - ByteArray
       - BytecodeArray
       - FixedArray
         - DescriptorArray
         - LiteralsArray
         - BindingsArray
         - HashTable
           - Dictionary
           - StringTable
           - CompilationCacheTable
           - CodeCacheHashTable
           - MapCache
         - OrderedHashTable
           - OrderedHashSet
           - OrderedHashMap
         - Context
         - TypeFeedbackMetadata
         - TypeFeedbackVector
         - ScopeInfo
         - TransitionArray
         - ScriptContextTable
         - WeakFixedArray
       - FixedDoubleArray
     - Name
       - String
         - SeqString
           - SeqOneByteString
           - SeqTwoByteString
         - SlicedString
         - ConsString
         - ExternalString
           - ExternalOneByteString
           - ExternalTwoByteString
         - InternalizedString
           - SeqInternalizedString
             - SeqOneByteInternalizedString
             - SeqTwoByteInternalizedString
           - ConsInternalizedString
           - ExternalInternalizedString
             - ExternalOneByteInternalizedString
             - ExternalTwoByteInternalizedString
       - Symbol
     - HeapNumber
     - Simd128Value
       - Float32x4
       - Int32x4
       - Uint32x4
       - Bool32x4
       - Int16x8
       - Uint16x8
       - Bool16x8
       - Int8x16
       - Uint8x16
       - Bool8x16
     - Cell
     - PropertyCell
     - Code
     - Map
     - Oddball
     - Foreign
     - SharedFunctionInfo
     - Struct
       - Box
       - AccessorInfo
         - ExecutableAccessorInfo
       - AccessorPair
       - AccessCheckInfo
       - InterceptorInfo
       - CallHandlerInfo
       - TemplateInfo
         - FunctionTemplateInfo
         - ObjectTemplateInfo
       - Script
       - TypeSwitchInfo
       - DebugInfo
       - BreakPointInfo
       - CodeCache
       - PrototypeInfo
     - WeakCell

 Formats of Object*:
  Smi:        [31 bit signed int] 0
  HeapObject: [32 bit direct pointer] (4 byte aligned) | 01
"""

import struct
import traceback
from v8_globals_48_0_2564_8 import *
from peda import config
from peda.utils import *


def has_smi_tag(v):
    return v & kSmiTagMask == kSmiTag


def has_failure_tag(v):
    return v & kFailureTagMask == kFailureTag


def has_heap_object_tag(v):
    return v & kHeapObjectTagMask == kHeapObjectTag


def raw_heap_object(v):
    return v - kHeapObjectTag


def smi_to_int_32(v):
    v &= kAllBits
    if (v & kTopBit32) == kTopBit32:
        return ((v & kAllBits) >> kSmiShiftBits32) - 2147483648
    else:
        return (v & kAllBits) >> kSmiShiftBits32


def smi_to_int_64(v):
    return v >> kSmiShiftBits64


def smi_to_int(v, bitness=32):
    if not has_smi_tag(v):
        return v
    if bitness == 32:
        return smi_to_int_32(v)
    else:
        return smi_to_int_64(v)


def decode_v8_value(v, bitness=32):
    base_str = 'v8[%x]' % v
    if has_smi_tag(v):
        if bitness == 32:
            return base_str + (" SMI(%d)" % smi_to_int_32(v))
        else:
            return base_str + (" SMI(%d)" % smi_to_int_64(v))
    elif has_failure_tag(v):
        return base_str + " (failure)"
    elif has_heap_object_tag(v):
        return base_str + (" H(0x%x)" % raw_heap_object(v))
    else:
        return base_str


def to_qword(data, unpack=True):
    num = len(data) // kDoubleSize
    result = struct.unpack('<' + 'Q' * num, data)
    return result[0] if unpack is True and num == 1 else result


def to_dword(data, unpack=True):
    num = len(data) // kPointerSize
    result = struct.unpack('<' + 'I' * num, data)
    return result[0] if unpack is True and num == 1 else result


def to_byte(data, unpack=True):
    num = len(data) // kCharSize
    result = struct.unpack('<' + 'B' * num, data)
    return result[0] if unpack is True and num == 1 else result


def to_double(data, unpack=True):
    num = len(data) // kDoubleSize
    result = struct.unpack('<' + 'd' * num, data)
    return result[0] if unpack is True and num == 1 else result


def to_boolean(value, bit_position):
    return (value & (1 << bit_position)) != 0


def read_mem(addr, size=kPointerSize):
    """
    Read memory using peda
    Args:
        addr: (int)
        size: size in byte (int)

    Returns: data (str)

    """
    return peda.readmem(addr, size)


def read(data, offset=0, size=kPointerSize):
    """
    Slice data using stream style
    Args:
        data: (str)
        offset: (int)
        size: (int)

    Returns: sliced data (str)

    """
    end = min(offset + size, len(data))
    return data[offset:end]


def get_dword_smi(data, offset=0):
    return smi_to_int(to_dword(read(data, offset)))


def get_dword(data, offset=0):
    return to_dword(read(data, offset))


def get_byte(data, offset=0):
    return to_byte(read(data, offset, kCharSize))


def BitField(shift, size=1):
    """
    Decorator for BitField
    Args:
        shift: (int)
        size: (int)

    Returns: Decorator function (function)

    """
    # A type U mask of bit field.  To use all bits of a type U of x bits
    # in a bitfield without compiler warnings we have to compute 2^x
    # without using a shift count of x in the computation.
    kOne = 1
    kMask = ((kOne << shift) << size) - (kOne << shift)
    kShift = shift
    kSize = size
    kNext = kShift + kSize

    def handle_func(func):
        def handle_args(*args, **kwargs):
            value = func(*args, **kwargs)
            return (value & kMask) >> shift

        return handle_args

    return handle_func


######################################################################################
#                                   JS classes                                       #
######################################################################################

class Object:
    """
    class Object
    Object is the abstract superclass for all classes in the
    object hierarchy.
    Object does not use any virtual functions to avoid the
    allocation of the C++ vtable.
    Since both Smi and HeapObject are subclasses of Object no
    data members can be present in Object.
    """
    kHeaderSize = 0

    kSize = kHeaderSize  # for mem dump needed

    def __init__(self, handle):
        if not isinstance(handle, Handle):
            raise RuntimeError('Invalid Handle')
        self.handle = handle
        self.data = None
        self.size = None
        self.result = []
        self.update_size(self.kSize)

    def update_size(self, size):
        if self.size < size:
            self.data = self.handle.data(size)
            if not self.data:
                warning('Got invalid heap object size.')
                raise RuntimeError
            self.size = size

    def increase_size(self, size):
        self.update_size(self.size + size)

    def parse(self):
        """
        Parse wrapper function
        Returns: parse result (list)

        """
        self.do_parse()
        return self.result

    def append(self, s):
        self.result.append(s)

    def do_parse(self):
        """
        Parse chains. All class use this function to modify self.result
        Returns: None

        """
        pass


class HeapObject(Object):
    """
    class HeapObject: public Object;
    HeapObject is the superclass for all classes describing heap allocated
    objects.
    """
    kMapOffset = Object.kHeaderSize
    kHeaderSize = kMapOffset + kPointerSize

    kSize = kHeaderSize  # for mem dump needed

    @staticmethod
    def get_map_addr(data):
        return get_dword(data, HeapObject.kMapOffset)

    # ---  support for get object size ---
    @staticmethod
    def get_object_size(data):
        """
            Copy and modify from int HeapObject::SizeFromMap(Map* map)
            Args:
                map_object: instance of Map (Map)

            Returns: object size (int)

            """
        map_addr = HeapObject.get_map_addr(data)
        map_object = Map(Handle(map_addr))

        instance_size = map_object.get_instance_size(map_object.data)
        if instance_size != kVariableSizeSentinel:
            return instance_size
        # Only inline the most frequent cases.
        instance_type = map_object.get_instance_type(map_object.data)
        if instance_type == InstanceType.FIXED_ARRAY_TYPE:
            return FixedArray.kHeaderSize + kPointerSize * FixedArray.get_length(data)
        if instance_type == InstanceType.ONE_BYTE_STRING_TYPE or instance_type == InstanceType.ONE_BYTE_INTERNALIZED_STRING_TYPE:
            return SeqOneByteString.kHeaderSize + kCharSize * SeqOneByteString.get_length(data)
        if instance_type == InstanceType.BYTE_ARRAY_TYPE:
            return ByteArray.kHeaderSize + ByteArray.get_length(data)
        if instance_type == InstanceType.BYTECODE_ARRAY_TYPE:
            # todo to add
            return 4
        if instance_type == InstanceType.FREE_SPACE_TYPE:
            return FreeSpace.get_size(data)
        if instance_type == InstanceType.STRING_TYPE or instance_type == InstanceType.INTERNALIZED_STRING_TYPE:
            return SeqTwoByteString.kHeaderSize + kShortSize * SeqTwoByteString.get_length(data)
        if instance_type == InstanceType.FIXED_DOUBLE_ARRAY_TYPE:
            return FixedDoubleArray.kHeaderSize + kDoubleSize * FixedDoubleArray.get_length(data)
        if InstanceType.FIRST_FIXED_TYPED_ARRAY_TYPE <= instance_type <= InstanceType.LAST_FIXED_TYPED_ARRAY_TYPE:
            return OBJECT_POINTER_ALIGN(
                FixedTypedArrayBase.kDataOffset + FixedTypedArrayBase.get_data_size_from_instance(data, instance_type))
        return RoundUp(Code.kHeaderSize + Code.get_body_size(data), kCodeAlignment)

    def do_parse(self):
        Object.do_parse(self)
        self.append('kMapAddr: 0x%x' % HeapObject.get_map_addr(self.data))


class HeapNumber(HeapObject):
    """
    class HeapNumber: public HeapObject;
    The HeapNumber class describes heap allocated numbers that cannot be
    represented in a Smi (small integer)
    """
    kValueOffset = HeapObject.kHeaderSize
    kMantissaOffset = kValueOffset
    kExponentOffset = kValueOffset + 4
    kSize = kValueOffset + kDoubleSize

    kSignMask = 0x80000000
    kExponentMask = 0x7ff00000
    kMantissaMask = 0xfffff
    kMantissaBits = 52
    kExponentBits = 11
    kExponentBias = 1023
    kExponentShift = 20
    kInfinityOrNanExponent = (kExponentMask >> kExponentShift) - kExponentBias
    kMantissaBitsInTopWord = 20
    kNonMantissaBitsInTopWord = 12

    @staticmethod
    def get_value(data):
        return to_double(read(data, HeapNumber.kValueOffset, kDoubleSize))

    @staticmethod
    def get_exponent(data):
        return ((get_dword(data, HeapNumber.kExponentOffset) & HeapNumber.kExponentMask) >>
                HeapNumber.kExponentShift) - HeapNumber.kExponentBias

    @staticmethod
    def get_sign(data):
        return get_dword(data, HeapNumber.kExponentOffset) & HeapNumber.kSignMask

    def do_parse(self):
        HeapObject.do_parse(self)
        self.append('kValue: %f' % HeapNumber.get_value(self.data))
        self.append('\tExponent: 0x%x' % HeapNumber.get_exponent(self.data))
        self.append('\tSign: 0x%x' % HeapNumber.get_sign(self.data))


class FixedArrayBase(HeapObject):
    """
    class FixedArrayBase: public HeapObject;
    Common superclass for FixedArrays that allow implementations to share
    common accessors and some code paths.
    """
    # Layout description.
    # Length is smi tagged when it is stored.
    kLengthOffset = HeapObject.kHeaderSize
    kHeaderSize = kLengthOffset + kPointerSize

    kSize = kHeaderSize  # for mem dump needed

    @staticmethod
    def get_length(data):
        return get_dword_smi(data, FixedArrayBase.kLengthOffset)

    def do_parse(self):
        HeapObject.do_parse(self)
        self.append('kLength: 0x%x' % FixedArrayBase.get_length(self.data))


class FixedArray(FixedArrayBase):
    """
    class FixedArray: public FixedArrayBase;
    FixedArray describes fixed-sized arrays with element type Object*.
    """

    # Maximal allowed size, in bytes, of a single FixedArray.
    # Prevents overflowing size computations, as well as extreme memory
    # consumption.
    kMaxSize = 128 * MB * kPointerSize
    # Maximally allowed length of a FixedArray.
    kMaxLength = (kMaxSize - FixedArrayBase.kHeaderSize) // kPointerSize

    def get_elements(self):
        length = FixedArray.get_length(self.data)
        if length == 0:
            return []
        self.increase_size(kPointerSize * length)
        elements = to_dword(read(self.data, self.kSize, kPointerSize * length), False)
        return elements

    def do_parse(self):
        FixedArrayBase.do_parse(self)
        elements = ',\t'.join([str(smi_to_int(i)) if has_smi_tag(i) else '0x%x' % i for i in self.get_elements()])
        self.append('Elements: (Addr 0x%x)  ==>  [%s]  (Smi casted)' % (self.handle.decode() + self.kSize, elements))


class FixedDoubleArray(FixedArrayBase):
    """
    class FixedDoubleArray: public FixedArrayBase;
    FixedDoubleArray describes fixed-sized arrays with element type double.
    """
    kMaxSize = 512 * MB
    kMaxLength = (kMaxSize - FixedArrayBase.kHeaderSize) // kDoubleSize

    def get_elements(self):
        length = FixedDoubleArray.get_length(self.data)
        if length == 0:
            return []
        self.increase_size(length * kDoubleSize)
        elements = to_double(read(self.data, self.kSize, kDoubleSize * length), False)
        return elements

    def get_representation(self):
        length = FixedDoubleArray.get_length(self.data)
        if length == 0:
            return []
        # Note that size already increased
        representations = to_qword(read(self.data, self.kSize, kDoubleSize * length), False)
        return representations

    def get_representation_dwords(self):
        length = FixedDoubleArray.get_length(self.data)
        if length == 0:
            return []
        # Note that size already increased
        length *= 2
        representations = to_dword(read(self.data, self.kSize, kPointerSize * length), False)
        return representations

    def do_parse(self):
        FixedArrayBase.do_parse(self)
        elements = ',\t'.join(['%f' % i for i in self.get_elements()])
        representations = ',\t'.join(['0x%x' % i for i in self.get_representation()])
        dwords = ',\t'.join(['0x%x' % i for i in self.get_representation_dwords()])
        self.append('Elements: (Addr 0x%x)  ==>  [%s]' % (self.handle.decode() + self.kSize, elements))
        self.append('\tRepresentations  ==>  [%s]' % representations)
        self.append('\tDword Representations  ==>  [%s]' % dwords)


class ByteArray(FixedArrayBase):
    """
    class ByteArray: public FixedArrayBase;
    ByteArray represents fixed sized byte arrays.  Used for the relocation info
    that is attached to code objects.
    """
    # Layout description.
    kAlignedSize = OBJECT_POINTER_ALIGN(FixedArrayBase.kHeaderSize)

    # Maximal memory consumption for a single ByteArray.
    kMaxSize = 512 * MB
    # Maximal length of a single ByteArray.
    kMaxLength = kMaxSize - FixedArrayBase.kHeaderSize

    def get_elements(self):
        length = FixedArray.get_length(self.data)
        if length == 0:
            return []
        self.increase_size(length)
        elements = to_byte(read(self.data, self.kSize, length))
        if length == 1:
            elements = [elements]
        elements = [str(i) for i in elements]
        return elements

    def do_parse(self):
        FixedArrayBase.do_parse(self)
        self.append(
            'Elements: (Addr 0x%x)  ==>  [%s]' % (self.handle.decode() + self.kSize, ',\t'.join(self.get_elements())))


class FixedTypedArrayBase(FixedArrayBase):
    """
    class FixedTypedArrayBase: public FixedArrayBase;
    """
    kBasePointerOffset = FixedArrayBase.kHeaderSize
    kExternalPointerOffset = kBasePointerOffset + kPointerSize
    kHeaderSize = DOUBLE_POINTER_ALIGN(kExternalPointerOffset + kPointerSize)
    kDataOffset = kHeaderSize
    kSize = kHeaderSize  # for mem dump needed

    # (Type, type, TYPE, C type, element_size)
    TYPED_ARRAYS = [('Uint8', 'uint8', 'UINT8', 'uint8_t', 1),
                    ('Int8', 'int8', 'INT8', 'int8_t', 1),
                    ('Uint16', 'uint16', 'UINT16', 'uint16_t', 2),
                    ('Int16', 'int16', 'INT16', 'int16_t', 2),
                    ('Uint32', 'uint32', 'UINT32', 'uint32_t', 4),
                    ('Int32', 'int32', 'INT32', 'int32_t', 4),
                    ('Float32', 'float32', 'FLOAT32', 'float', 4),
                    ('Float64', 'float64', 'FLOAT64', 'double', 8),
                    ('Uint8Clamped', 'uint8_clamped', 'UINT8_CLAMPED', 'uint8_t', 1)]

    @staticmethod
    def get_base_pointer_addr(data):
        return get_dword(data, FixedTypedArrayBase.kBasePointerOffset)

    @staticmethod
    def get_external_pointer_addr(data):
        return get_dword(data, FixedTypedArrayBase.kExternalPointerOffset)

    @staticmethod
    def get_data_ptr(data):
        return FixedTypedArrayBase.get_base_pointer_addr(data) + FixedTypedArrayBase.get_external_pointer_addr(data)

    @staticmethod
    def get_element_size_from_instance(instance_type_num):
        instance_type_name = get_instance_type_name(instance_type_num)
        for i in FixedTypedArrayBase.TYPED_ARRAYS:
            if 'FIXED_%s_ARRAY_TYPE' % i[2] in instance_type_name:
                return i[-1]
        return 0

    @staticmethod
    def get_data_size_from_instance(data, instance_type_num):
        element_size = FixedTypedArrayBase.get_element_size_from_instance(instance_type_num)
        return FixedArrayBase.get_length(data) * element_size

    def do_parse(self):
        FixedArrayBase.do_parse(self)
        self.append('kBasePointerAddr: 0x%x' % FixedTypedArrayBase.get_base_pointer_addr(self.data))
        self.append('kExternalPointerAddr: 0x%x' % FixedTypedArrayBase.get_external_pointer_addr(self.data))


class FixedTypedArray(FixedTypedArrayBase):
    """
    template <class Traits>
    class FixedTypedArray: public FixedTypedArrayBase;
    """
    ElementType = int
    kInstanceType = InstanceType.FIXED_UINT8_ARRAY_TYPE

    def get_scalars(self):
        """
        Get scalar of this FixedTypedArray
        Returns:
            Scalars: [self.ElementType ..] not str!
        """
        length = self.get_length(self.data)
        element_size = self.get_element_size_from_instance(self.kInstanceType)
        data_ptr = self.get_data_ptr(self.data)
        data = read_mem(data_ptr, length * element_size)
        if data == None:
            return []

        pfs = {8: 'B', 16: 'H', 32: 'I', 64: 'Q'}[8 * element_size]
        elements = struct.unpack('<' + pfs * length, data)

        return [self.ElementType(i) for i in elements]

    def do_parse(self):
        FixedTypedArrayBase.do_parse(self)
        scalars = ',\t'.join(['0x%x' % i for i in self.get_scalars()])
        self.append('ScalarsAddr: 0x%x  ==>  [%s]  (Smi not casted)' % (self.get_data_ptr(self.data), scalars))


class FixedUint8Array(FixedTypedArray):
    """
    FixedTypedArray<Uint8>;
    """
    pass


class FixedInt8Array(FixedTypedArray):
    """
    FixedTypedArray<Int8>;
    """
    kInstanceType = InstanceType.FIXED_INT8_ARRAY_TYPE


class FixedUint16Array(FixedTypedArray):
    """
    FixedTypedArray<Uint16>
    """
    kInstanceType = InstanceType.FIXED_UINT16_ARRAY_TYPE


class FixedInt16Array(FixedTypedArray):
    """
    FixedTypedArray<Int16>;
    """
    kInstanceType = InstanceType.FIXED_INT16_ARRAY_TYPE


class FixedUint32Array(FixedTypedArray):
    """
    FixedTypedArray<Uint32>;
    """
    kInstanceType = InstanceType.FIXED_UINT32_ARRAY_TYPE


class FixedInt32Array(FixedTypedArray):
    """
    FixedTypedArray<Int32>;
    """
    kInstanceType = InstanceType.FIXED_INT32_ARRAY_TYPE


class FixedFloat32Array(FixedTypedArray):
    """
    FixedTypedArray<Float32>;
    """
    ElementType = float
    kInstanceType = InstanceType.FIXED_FLOAT32_ARRAY_TYPE


class FixedFloat64Array(FixedTypedArray):
    """
    FixedTypedArray<Float64>;
    """
    ElementType = float
    kInstanceType = InstanceType.FIXED_FLOAT64_ARRAY_TYPE


class FixedUint8ClampedArray(FixedTypedArray):
    """
    FixedTypedArray<Uint8Clamped>
    """
    kInstanceType = InstanceType.FIXED_UINT8_CLAMPED_ARRAY_TYPE


class FreeSpace(HeapObject):
    """
    class FreeSpace: public HeapObject;
    FreeSpace are fixed-size free memory blocks used by the heap and GC.
    They look like heap objects (are heap object tagged and have a map) so that
    the heap remains iterable.  They have a size and a next pointer.
    The next pointer is the raw address of the next FreeSpace object (or NULL)
    in the free list.
    """
    # [size]: size of the free space including the header.
    kSizeOffset = HeapObject.kHeaderSize
    kNextOffset = POINTER_SIZE_ALIGN(kSizeOffset + kPointerSize)

    kSize = kNextOffset + kPointerSize  # for mem dump needed

    @staticmethod
    def get_size(data):
        return get_dword_smi(data, FreeSpace.kSizeOffset)

    def do_parse(self):
        HeapObject.do_parse(self)
        self.append('kSize: 0x%x' % FreeSpace.get_size(self.data))


class Code(HeapObject):
    """
    class Code: public HeapObject;
    Code describes objects with on-the-fly generated machine code.
    """
    kMaxLoopNestingMarker = 6
    # kConstantPoolSize = FLAG_enable_embedded_constant_pool ? kIntSize: 0
    kConstantPoolSize = 0
    kRelocationInfoOffset = HeapObject.kHeaderSize
    kHandlerTableOffset = kRelocationInfoOffset + kPointerSize
    kDeoptimizationDataOffset = kHandlerTableOffset + kPointerSize
    kTypeFeedbackInfoOffset = kDeoptimizationDataOffset + kPointerSize
    kNextCodeLinkOffset = kTypeFeedbackInfoOffset + kPointerSize
    kGCMetadataOffset = kNextCodeLinkOffset + kPointerSize
    kInstructionSizeOffset = kGCMetadataOffset + kPointerSize
    kICAgeOffset = kInstructionSizeOffset + kIntSize
    kFlagsOffset = kICAgeOffset + kIntSize
    kKindSpecificFlags1Offset = kFlagsOffset + kIntSize
    kKindSpecificFlags2Offset = kKindSpecificFlags1Offset + kIntSize
    kPrologueOffset = kKindSpecificFlags2Offset + kIntSize
    kConstantPoolOffset = kPrologueOffset + kIntSize
    kHeaderPaddingStart = kConstantPoolOffset + kConstantPoolSize
    kHeaderSize = (kHeaderPaddingStart + kCodeAlignmentMask) & ~kCodeAlignmentMask
    kSize = kHeaderSize  # for mem dump needed

    @staticmethod
    def get_relocation_info_addr(data):
        return get_dword(data, Code.kRelocationInfoOffset)

    @staticmethod
    def get_handler_table_addr(data):
        return get_dword(data, Code.kHandlerTableOffset)

    @staticmethod
    def get_deoptimization_data_addr(data):
        return get_dword(data, Code.kDeoptimizationDataOffset)

    @staticmethod
    def get_type_feedback_info_addr(data):
        return get_dword(data, Code.kTypeFeedbackInfoOffset)

    @staticmethod
    def get_next_code_link_addr(data):
        return get_dword(data, Code.kNextCodeLinkOffset)

    @staticmethod
    def get_g_c_metadata_addr(data):
        return get_dword(data, Code.kGCMetadataOffset)

    @staticmethod
    def get_instruction_size_addr(data):
        return get_dword(data, Code.kInstructionSizeOffset)

    @staticmethod
    def get_i_c_age_addr(data):
        return get_dword(data, Code.kICAgeOffset)

    @staticmethod
    def get_flags_addr(data):
        return get_dword(data, Code.kFlagsOffset)

    @staticmethod
    def get_kind_specific_flags_1_addr(data):
        return get_dword(data, Code.kKindSpecificFlags1Offset)

    @staticmethod
    def get_kind_specific_flags_2_addr(data):
        return get_dword(data, Code.kKindSpecificFlags2Offset)

    @staticmethod
    def get_prologue_addr(data):
        return get_dword(data, Code.kPrologueOffset)

    @staticmethod
    def get_constant_pool_addr(data):
        return get_dword(data, Code.kConstantPoolOffset)

    # Support for get_object_size
    @staticmethod
    def get_body_size(data):
        return RoundUp(Code.get_instruction_size_addr(data), kObjectAlignment)

    def do_parse(self):
        HeapObject.do_parse(self)
        self.append('kRelocationInfoAddr: 0x%x' % Code.get_relocation_info_addr(self.data))
        self.append('kHandlerTableAddr: 0x%x' % Code.get_handler_table_addr(self.data))
        self.append('kDeoptimizationDataAddr: 0x%x' % Code.get_deoptimization_data_addr(self.data))
        self.append('kTypeFeedbackInfoAddr: 0x%x' % Code.get_type_feedback_info_addr(self.data))
        self.append('kNextCodeLinkAddr: 0x%x' % Code.get_next_code_link_addr(self.data))
        self.append('kGCMetadataAddr: 0x%x' % Code.get_g_c_metadata_addr(self.data))
        self.append('kInstructionSizeAddr: 0x%x' % Code.get_instruction_size_addr(self.data))
        self.append('kICAgeAddr: 0x%x' % Code.get_i_c_age_addr(self.data))
        self.append('kFlagsAddr: 0x%x' % Code.get_flags_addr(self.data))
        self.append('kKindSpecificFlags1Addr: 0x%x' % Code.get_kind_specific_flags_1_addr(self.data))
        self.append('kKindSpecificFlags2Addr: 0x%x' % Code.get_kind_specific_flags_2_addr(self.data))
        self.append('kPrologueAddr: 0x%x' % Code.get_prologue_addr(self.data))
        self.append('kConstantPoolAddr: 0x%x' % Code.get_constant_pool_addr(self.data))


class Map(HeapObject):
    """
    class Map: public HeapObject;
    All heap objects have a Map that describes their structure.
     A Map contains information about:
     - Size information about the object
     - How to iterate over an object (for garbage collection)
    """
    kInstanceSizesOffset = HeapObject.kHeaderSize
    kInstanceAttributesOffset = kInstanceSizesOffset + kIntSize
    kBitField3Offset = kInstanceAttributesOffset + kIntSize
    kPrototypeOffset = kBitField3Offset + kPointerSize
    kConstructorOrBackPointerOffset = kPrototypeOffset + kPointerSize
    # Storage for the transition array is overloaded to directly contain a back
    # pointer if unused. When the map has transitions, the back pointer is
    # transferred to the transition array and accessed through an extra
    # indirection.
    kTransitionsOrPrototypeInfoOffset = kConstructorOrBackPointerOffset + kPointerSize
    kDescriptorsOffset = kTransitionsOrPrototypeInfoOffset + kPointerSize
    kLayoutDecriptorOffset = 1
    kCodeCacheOffset = kDescriptorsOffset + kPointerSize
    kDependentCodeOffset = kCodeCacheOffset + kPointerSize
    kWeakCellCacheOffset = kDependentCodeOffset + kPointerSize
    kSize = kWeakCellCacheOffset + kPointerSize

    kProtoTransitionHeaderSize = 1
    kProtoTransitionNumberOfEntriesOffset = 0
    kProtoTransitionElementsPerEntry = 2
    kProtoTransitionPrototypeOffset = 0
    kProtoTransitionMapOffset = 1
    # When you set the prototype of an object using the __proto__ accessor you
    # need a new map for the object (the prototype is stored in the map).  In
    # order not to multiply maps unnecessarily we store these as transitions in
    # the original map.  That way we can transition to the same map if the same
    # prototype is set, rather than creating a new map every time.  The
    # transitions are in the form of a map where the keys are prototype objects
    # and the values are the maps the are transitioned to.
    kMaxCachedPrototypeTransitions = 256
    kMaxPreAllocatedPropertyFields = 255

    # Layout of pointer fields. Heap iteration code relies on them
    # being continuously allocated.
    kPointerFieldsBeginOffset = kPrototypeOffset
    kPointerFieldsEndOffset = kSize

    # Byte offsets within kInstanceSizesOffset.
    kInstanceSizeOffset = kInstanceSizesOffset + 0
    kInObjectPropertiesOrConstructorFunctionIndexByte = 1
    kInObjectPropertiesOrConstructorFunctionIndexOffset = kInstanceSizesOffset + kInObjectPropertiesOrConstructorFunctionIndexByte
    kUnusedByte = 2
    kUnusedOffset = kInstanceSizesOffset + kUnusedByte
    kVisitorIdByte = 3
    kVisitorIdOffset = kInstanceSizesOffset + kVisitorIdByte

    # Byte offsets within kInstanceAttributesOffset attributes.
    # if V8_TARGET_LITTLE_ENDIAN
    # Order instance type and bit field together such that they can be loaded
    # together as a 16-bit word with instance type in the lower 8 bits regardless
    # of endianess. Also provide endian-independent offset to that 16-bit word.
    kInstanceTypeOffset = kInstanceAttributesOffset + 0
    kBitFieldOffset = kInstanceAttributesOffset + 1
    # else
    # kBitFieldOffset = kInstanceAttributesOffset + 0
    # kInstanceTypeOffset = kInstanceAttributesOffset + 1
    # endif
    kInstanceTypeAndBitFieldOffset = kInstanceAttributesOffset + 0
    kBitField2Offset = kInstanceAttributesOffset + 2
    kUnusedPropertyFieldsByte = 3
    kUnusedPropertyFieldsOffset = kInstanceAttributesOffset + 3

    # Bit positions for bit field.
    kHasNonInstancePrototype = 0
    kIsCallable = 1
    kHasNamedInterceptor = 2
    kHasIndexedInterceptor = 3
    kIsUndetectable = 4
    kIsObserved = 5
    kIsAccessCheckNeeded = 6
    kIsConstructor = 7

    # Bit positions for bit field 2
    kIsExtensible = 0

    # Derived values from bit field 2
    ElementsKindBits_kShift = 3
    kMaximumBitField2FastElementValue = (ElementsKind.FAST_ELEMENTS + 1) << ElementsKindBits_kShift - 1
    kMaximumBitField2FastSmiElementValue = (ElementsKind.FAST_SMI_ELEMENTS + 1) << ElementsKindBits_kShift - 1
    kMaximumBitField2FastHoleyElementValue = (ElementsKind.FAST_HOLEY_ELEMENTS + 1) << ElementsKindBits_kShift - 1
    kMaximumBitField2FastHoleySmiElementValue = (
                                                        ElementsKind.FAST_HOLEY_SMI_ELEMENTS + 1) << ElementsKindBits_kShift - 1

    # ------ kInstanceSizesOffset details ---------
    @staticmethod
    def get_instance_sizes(data):
        return get_dword(data, Map.kInstanceSizesOffset)

    @staticmethod
    def get_instance_size(data):
        return get_byte(data, Map.kInstanceSizeOffset) << kPointerSizeLog2

    @staticmethod
    def get_in_object_properties_or_constructor_function_index(data):
        return get_byte(data, Map.kInObjectPropertiesOrConstructorFunctionIndexOffset)

    @staticmethod
    def get_unused_offset_in_instance_sizes(data):
        return get_byte(data, Map.kUnusedOffset)

    @staticmethod
    def get_visitor_id(data):
        return get_byte(data, Map.kVisitorIdOffset)

    # ------ kInstanceAttributesOffset details ---------
    @staticmethod
    def get_instance_attributes(data):
        return get_dword(data, Map.kInstanceAttributesOffset)

    @staticmethod
    def get_instance_type(data):
        return get_byte(data, Map.kInstanceAttributesOffset)

    @staticmethod
    def get_class(data):
        return Map.type_to_class(Map.get_instance_type(data))

    @staticmethod
    def type_to_class(type_num):
        if type_num in TYPE_TO_CLASS:
            return TYPE_TO_CLASS.get(type_num)
        warning('InstanceType 0x%x (%s) not supported.' % (type_num, get_instance_type_name(type_num)))
        return None

    @staticmethod
    def get_instance_type_name(data):
        type_num = Map.get_instance_type(data)
        return get_instance_type_name(type_num)

    # ------       Handle BitField       ---------
    @staticmethod
    def get_bit_field(data):
        return get_byte(data, Map.kBitFieldOffset)

    @staticmethod
    def has_non_instance_prototype(data):
        return ((1 << Map.kHasNonInstancePrototype) & Map.get_bit_field(data)) != 0

    # Tells whether the instance with this map should be ignored by the
    # Object.getPrototypeOf() function and the __proto__ accessor.
    @staticmethod
    def is_callable(data):
        return ((1 << Map.kIsCallable) & Map.get_bit_field(data)) != 0

    # Records and queries whether the instance has a named interceptor.
    @staticmethod
    def has_named_interceptor(data):
        return ((1 << Map.kHasNamedInterceptor) & Map.get_bit_field(data)) != 0

    # Records and queries whether the instance has an indexed interceptor.
    @staticmethod
    def has_indexed_interceptor(data):
        return ((1 << Map.kHasIndexedInterceptor) & Map.get_bit_field(data)) != 0

    # Tells whether the instance is undetectable.
    # An undetectable object is a special class of JSObject: 'typeof' operator
    # returns undefined, ToBoolean returns false. Otherwise it behaves like
    # a normal JS object.  It is useful for implementing undetectable
    # document.all in Firefox & Safari.
    # See https:#bugzilla.mozilla.org/show_bug.cgi?id=248549.
    @staticmethod
    def is_undetectable(data):
        return ((1 << Map.kIsUndetectable) & Map.get_bit_field(data)) != 0

    # Tells whether the instance has a call-as-function handler.
    @staticmethod
    def is_observed(data):
        return ((1 << Map.kIsObserved) & Map.get_bit_field(data)) != 0

    @staticmethod
    def is_access_check_needed(data):
        return ((1 << Map.kIsAccessCheckNeeded) & Map.get_bit_field(data)) != 0

    @staticmethod
    def is_constructor(data):
        return ((1 << Map.kIsConstructor) & Map.get_bit_field(data)) != 0

    # ------       Handle BitField2       ---------
    @staticmethod
    def get_bit_field2(data):
        return get_byte(data, Map.kBitField2Offset)

    @staticmethod
    def is_extensible(data):
        return ((1 << Map.kIsExtensible) & Map.get_bit_field2(data)) != 0

    #  Bit 1 is free.

    @staticmethod
    @BitField(2)
    def is_prototype_map(data):
        return Map.get_bit_field2(data)

    @staticmethod
    @BitField(3, 5)
    def get_elements_kind(data):
        return Map.get_bit_field2(data)

    @staticmethod
    def get_elements_kind_name(data):
        kind_num = Map.get_elements_kind(data)
        return get_elements_kind_name(kind_num)

    @staticmethod
    def get_unused_property_fields(data):
        return get_byte(data, Map.kUnusedPropertyFieldsOffset)

    # ------       Handle BitField3       ---------
    @staticmethod
    def get_bit_field3(data):
        return get_dword(data, Map.kBitField3Offset)

    @staticmethod
    @BitField(0, kDescriptorIndexBitCount)
    def get_enum_length(data):
        return Map.get_bit_field3(data)

    @staticmethod
    @BitField(kDescriptorIndexBitCount, kDescriptorIndexBitCount)
    def get_number_of_own_descriptors(data):
        return Map.get_bit_field3(data)

    @staticmethod
    @BitField(20)
    def is_dictionary_map(data):
        return Map.get_bit_field3(data)

    @staticmethod
    @BitField(21)
    def is_owns_dexcriptors(data):
        return Map.get_bit_field3(data)

    @staticmethod
    @BitField(22)
    def is_hidden_prototype(data):
        return Map.get_bit_field3(data)

    @staticmethod
    @BitField(23)
    def is_deprecated(data):
        return Map.get_bit_field3(data)

    @staticmethod
    @BitField(24)
    def is_unstable(data):
        return Map.get_bit_field3(data)

    @staticmethod
    @BitField(25)
    def is_migration_target(data):
        return Map.get_bit_field3(data)

    @staticmethod
    @BitField(26)
    def is_strong(data):
        return Map.get_bit_field3(data)

    # Keep this bit field at the very end for better code in
    # Builtins::kJSConstructStubGeneric stub.
    # This counter is used for in-object slack tracking and for map aging.
    # The in-object slack tracking is considered enabled when the counter is
    # in the range [kSlackTrackingCounterStart, kSlackTrackingCounterEnd].
    @staticmethod
    @BitField(28, 4)
    def counter(data):
        return Map.get_bit_field3(data)

    kSlackTrackingCounterStart = 14
    kSlackTrackingCounterEnd = 8
    kRetainingCounterStart = kSlackTrackingCounterEnd - 1
    kRetainingCounterEnd = 0

    # ------   End of Handle BitFields  ---------

    @staticmethod
    def get_prototype(data):
        return get_dword(data, Map.kPrototypeOffset)

    @staticmethod
    def get_constructor_or_back_pointer(data):
        return get_dword(data, Map.kConstructorOrBackPointerOffset)

    @staticmethod
    def get_transitions_or_prototype_info(data):
        return get_dword(data, Map.kTransitionsOrPrototypeInfoOffset)

    @staticmethod
    def get_descriptors(data):
        return get_dword(data, Map.kDescriptorsOffset)

    @staticmethod
    def get_code_cache(data):
        return get_dword(data, Map.kCodeCacheOffset)

    @staticmethod
    def get_dependent_code(data):
        return get_dword(data, Map.kDependentCodeOffset)

    @staticmethod
    def get_weak_cell_cache_addr(data):
        return get_dword(data, Map.kWeakCellCacheOffset)

    def do_parse(self):
        HeapObject.do_parse(self)
        self.append('kInstanceSizes: 0x%x'
                    '\n\tkInstanceSize: 0x%x (real size)'
                    '\n\tkInObjectPropertiesOrConstructorFunctionIndexOffset: 0x%x'
                    '\n\tkUnusedOffset: 0x%x'
                    '\n\tkVisitorId: 0x%x' %
                    (self.get_instance_sizes(self.data),
                     self.get_instance_size(self.data),
                     self.get_in_object_properties_or_constructor_function_index(self.data),
                     self.get_unused_offset_in_instance_sizes(self.data),
                     self.get_visitor_id(self.data)))
        self.append('kInstanceAttributes: 0x%x'
                    '\n\tkInstanceType: 0x%x (%s)'
                    # BitField
                    '\n\tkBitField: 0x%x'
                    '\n\t\tkHasNonInstancePrototype: 0x%x'
                    '\n\t\tkIsCallable: 0x%x'
                    '\n\t\tkHasNamedInterceptor: 0x%x'
                    '\n\t\tkHasIndexedInterceptor: 0x%x'
                    '\n\t\tkIsUndetectable: 0x%x'
                    '\n\t\tkIsObserved: 0x%x'
                    '\n\t\tkIsAccessCheckNeeded: 0x%x'
                    '\n\t\tkIsConstructor: 0x%x'
                    # BitField2
                    '\n\tkBitField2: 0x%x'
                    '\n\t\tkIsExtensible: 0x%x'
                    '\n\t\tIsPrototypeMap: 0x%x'
                    '\n\t\tElementsKind: 0x%x (%s)'
                    # kUnusedPropertyFields
                    '\n\tkUnusedPropertyFields: 0x%x'
                    %
                    (self.get_instance_attributes(self.data),
                     self.get_instance_type(self.data), self.get_instance_type_name(self.data),
                     # BitField
                     self.get_bit_field(self.data),
                     self.has_non_instance_prototype(self.data),
                     self.is_callable(self.data),
                     self.has_named_interceptor(self.data),
                     self.has_indexed_interceptor(self.data),
                     self.is_undetectable(self.data),
                     self.is_observed(self.data),
                     self.is_access_check_needed(self.data),
                     self.is_constructor(self.data),
                     # BitField2
                     self.get_bit_field2(self.data),
                     self.is_extensible(self.data),
                     self.is_prototype_map(self.data),
                     self.get_elements_kind(self.data), self.get_elements_kind_name(self.data),
                     # kUnusedPropertyFields
                     self.get_unused_property_fields(self.data)))
        self.append('kBitField3: 0x%x'
                    '\n\tEnumLengthBits: 0x%x'
                    '\n\tNumberOfOwnDescriptorsBits: 0x%x'
                    '\n\tIsDictionaryMap : 0x%x'
                    '\n\tIsOwnsDescriptors : 0x%x'
                    '\n\tIsHiddenPrototype : 0x%x'
                    '\n\tIsDeprecated : 0x%x'
                    '\n\tIsUnstable : 0x%x'
                    '\n\tIsMigrationTarget : 0x%x'
                    '\n\tIsStrong : 0x%x'
                    '\n\tCounter: 0x%x'
                    %
                    (self.get_bit_field3(self.data),
                     self.get_enum_length(self.data),
                     self.get_number_of_own_descriptors(self.data),
                     self.is_dictionary_map(self.data),
                     self.is_owns_dexcriptors(self.data),
                     self.is_hidden_prototype(self.data),
                     self.is_deprecated(self.data),
                     self.is_unstable(self.data),
                     self.is_migration_target(self.data),
                     self.is_strong(self.data),
                     self.counter(self.data)))
        self.append('kPrototype: 0x%x' % self.get_prototype(self.data))
        self.append('kConstructorOrBackPointerOffset: 0x%x' % self.get_constructor_or_back_pointer(self.data))
        self.append('kTransitionsOrPrototypeInfoOffset: 0x%x' % self.get_transitions_or_prototype_info(self.data))
        self.append('kDescriptors: 0x%x' % self.get_descriptors(self.data))
        self.append('kCodeCache: 0x%x' % self.get_code_cache(self.data))
        self.append('kDependentCode: 0x%x' % self.get_dependent_code(self.data))
        self.append('kWeakCellCache: 0x%x' % self.get_weak_cell_cache_addr(self.data))


class Name(HeapObject):
    """
    class Name: public HeapObject;
    The Name abstract class captures anything that can be used as a property
    name, i.e., strings and symbols.  All names store a hash value.
    """
    # Layout description.
    kHashFieldOffset = HeapObject.kHeaderSize
    kSize = kHashFieldOffset + kPointerSize

    # Mask constant for checking if a name has a computed hash code
    # and if it is a string that is an array index.  The least significant bit
    # indicates whether a hash code has been computed.  If the hash code has
    # been computed the 2nd bit tells whether the string can be used as an
    # array index.
    kHashNotComputedMask = 1
    kIsNotArrayIndexMask = 1 << 1
    kNofHashBitFields = 2

    # Shift constant retrieving hash code from hash field.
    kHashShift = kNofHashBitFields

    # Only these bits are relevant in the hash, since the top two are shifted
    # out.
    kHashBitMask = 0xffffffff >> kHashShift

    # Array index strings this short can keep their index in the hash field.
    kMaxCachedArrayIndexLength = 7

    # For strings which are array indexes the hash value has the string length
    # mixed into the hash, mainly to avoid a hash value of zero which would be
    # the case for the string '0'. 24 bits are used for the array index value.
    kArrayIndexValueBits = 24
    kArrayIndexLengthBits = kBitsPerInt - kArrayIndexValueBits - kNofHashBitFields

    @staticmethod
    def get_hash_field(data):
        return get_dword(data, Name.kHashFieldOffset)

    def do_parse(self):
        HeapObject.do_parse(self)
        self.append('kHashField: 0x%x' % self.get_hash_field(self.data))


class Symbol(Name):
    """
    class Symbol: public Name;
    ES6 symbols.
    """
    kNameOffset = Name.kSize
    kFlagsOffset = kNameOffset + kPointerSize
    kSize = kFlagsOffset + kPointerSize

    kPrivateBit = 0
    kOwnBit = 1

    @staticmethod
    def get_name_addr(data):
        return get_dword(data, Symbol.kNameOffset)

    @staticmethod
    def get_flags(data):
        return get_dword_smi(data, Symbol.kFlagsOffset)

    def do_parse(self):
        Name.do_parse(self)
        self.append('kNameAddr: 0x%x' % Symbol.get_name_addr(self.data))
        self.append('kFlagsAddr: 0x%x' % Symbol.get_flags(self.data))


class String(Name):
    """
    class String: public Name;
    The String abstract class captures JavaScript string values:

    Ecma-262:
     4.3.16 String Value
       A string value is a member of the type String and is a finite
       ordered sequence of zero or more 16-bit unsigned integer values.

    All string values have a length field.
    """
    # Layout description.
    kLengthOffset = Name.kSize
    kSize = kLengthOffset + kPointerSize

    # Array index strings this short can keep their index in the hash field.
    kMaxCachedArrayIndexLength = 7

    # For strings which are array indexes the hash value has the string length
    # mixed into the hash, mainly to avoid a hash value of zero which would be
    # the case for the string '0'. 24 bits are used for the array index value.
    kArrayIndexValueBits = 24
    kArrayIndexLengthBits = kBitsPerInt - kArrayIndexValueBits - Name.kNofHashBitFields

    # Maximum number of characters to consider when trying to convert a string
    # value into an array index.
    kMaxArrayIndexSize = 10

    # unibrow::Latin1::kMaxChar
    kMaxChar = 0xff

    # Max char codes.
    kMaxOneByteCharCode = kMaxChar
    kMaxOneByteCharCodeU = kMaxChar
    kMaxUtf16CodeUnit = 0xffff
    kMaxUtf16CodeUnitU = kMaxUtf16CodeUnit

    # Value of hash field containing computed hash equal to zero.
    kEmptyStringHash = Name.kIsNotArrayIndexMask

    # Maximal string length.
    kMaxLength = (1 << 28) - 16

    # Max length for computing hash. For strings longer than this limit the
    # string length is used as the hash value.
    kMaxHashCalcLength = 16383

    # Limit for truncation in short printing.
    kMaxShortPrintLength = 1024

    @staticmethod
    def get_length(data):
        return get_dword_smi(data, String.kLengthOffset)

    def do_parse(self):
        Name.do_parse(self)
        self.append('kLength: 0x%x' % self.get_length(self.data))


class SeqString(String):
    """
    class SeqString: public String;
    The SeqString abstract class captures sequential string values.
    """

    # Layout description.
    kHeaderSize = String.kSize

    kSize = kHeaderSize  # for mem dump needed

    def get_string(self):
        length = self.get_length(self.data)
        if isinstance(self, SeqTwoByteString):
            length *= 2
        self.increase_size(length)
        return read(self.data, self.kSize, length)

    def do_parse(self):
        String.do_parse(self)
        self.append('String: (Addr 0x%x)  ==>  "%s"' % (self.handle.decode() + self.kSize, self.get_string()))


class SeqOneByteString(SeqString):
    """
    class SeqOneByteString: public SeqString;
    The OneByteString class captures sequential one-byte string objects.
    Each character in the OneByteString is an one-byte character.
    """
    # Maximal memory usage for a single sequential one-byte string.
    kMaxSize = 512 * MB - 1


class SeqTwoByteString(SeqString):
    """
    class SeqTwoByteString: public SeqString;
    The TwoByteString class captures sequential unicode string objects.
    Each character in the TwoByteString is a two-byte uint16_t.
    """
    # Maximal memory usage for a single sequential two-byte string.
    kMaxSize = 512 * MB - 1


class ConsString(String):
    """
    class ConsString: public String;
    The ConsString class describes string values built by using the
    addition operator on strings.  A ConsString is a pair where the
    first and second components are pointers to other string values.
    One or both components of a ConsString can be pointers to other
    ConsStrings, creating a binary tree of ConsStrings where the leaves
    are non-ConsString string values.  The string value represented by
    a ConsString can be obtained by concatenating the leaf string
    values in a left-to-right depth-first traversal of the tree.
    """
    kFirstOffset = POINTER_SIZE_ALIGN(String.kSize)
    kSecondOffset = kFirstOffset + kPointerSize
    kSize = kSecondOffset + kPointerSize
    # Minimum length for a cons string.
    kMinLength = 13

    @staticmethod
    def get_first_addr(data):
        return get_dword(data, ConsString.kFirstOffset)

    @staticmethod
    def get_second_addr(data):
        return get_dword(data, ConsString.kSecondOffset)

    def do_parse(self):
        String.do_parse(self)
        self.append('kFirstAddr: 0x%x' % ConsString.get_first_addr(self.data))
        self.append('kSecondAddr: 0x%x' % ConsString.get_second_addr(self.data))


class SlicedString(String):
    """
    class SlicedString: public String;
    The Sliced String class describes strings that are substrings of another
    sequential string.  The motivation is to save time and memory when creating
    a substring.  A Sliced String is described as a pointer to the parent,
    the offset from the start of the parent string and the length.  Using
    a Sliced String therefore requires unpacking of the parent string and
    adding the offset to the start address.  A substring of a Sliced String
    are not nested since the double indirection is simplified when creating
    such a substring.
    Currently missing features are:
     - handling externalized parent strings
     - external strings as parent
     - truncating sliced string to enable otherwise unneeded parent to be GC'ed.
    """
    kParentOffset = POINTER_SIZE_ALIGN(String.kSize)
    kOffsetOffset = kParentOffset + kPointerSize
    kSize = kOffsetOffset + kPointerSize
    kMinLength = 13

    @staticmethod
    def get_parent_addr(data):
        return get_dword(data, SlicedString.kParentOffset)

    @staticmethod
    def get_offset_addr(data):
        return get_dword(data, SlicedString.kOffsetOffset)

    def do_parse(self):
        String.do_parse(self)
        self.append('kParentAddr: 0x%x' % SlicedString.get_parent_addr(self.data))
        self.append('kOffsetAddr: 0x%x' % SlicedString.get_offset_addr(self.data))


class ExternalString(String):
    """
    class ExternalString: public String;
    The ExternalString class describes string values that are backed by
    a string resource that lies outside the V8 heap.  ExternalStrings
    consist of the length field common to all strings, a pointer to the
    external resource.  It is important to ensure (externally) that the
    resource is not deallocated while the ExternalString is live in the
    V8 heap.

    The API expects that all ExternalStrings are created through the
    API.  Therefore, ExternalStrings should not be used internally.
    """
    kResourceOffset = POINTER_SIZE_ALIGN(String.kSize)
    kShortSize = kResourceOffset + kPointerSize
    kResourceDataOffset = kResourceOffset + kPointerSize
    kSize = kResourceDataOffset + kPointerSize
    kMaxShortLength = (kShortSize - SeqString.kHeaderSize) // kCharSize

    @staticmethod
    def get_resource_addr(data):
        return get_dword(data, ExternalString.kResourceOffset)

    @staticmethod
    def get_resource_data_addr(data):
        return get_dword(data, ExternalString.kResourceDataOffset)

    @staticmethod
    def get_resource_data(data):
        addr = ExternalString.get_resource_data_addr(data)
        length = ExternalString.get_length(data)
        return read_mem(addr, length)

    def do_parse(self):
        String.do_parse(self)
        self.append('kResourceAddr: 0x%x' % ExternalString.get_resource_addr(self.data))
        self.append('kResourceDataAddr: 0x%x ("%s")' %
                    (ExternalString.get_resource_data_addr(self.data), ExternalString.get_resource_data(self.data)))


class ExternalOneByteString(ExternalString):
    """
    class ExternalOneByteString : public ExternalString;
    The ExternalOneByteString class is an external string backed by an
    one-byte string.
    """


class Oddball(HeapObject):
    """
    class Oddball: public HeapObject;
    The Oddball describes objects null, undefined, true, and false.
    """
    # Layout description.
    kToStringOffset = HeapObject.kHeaderSize
    kToNumberOffset = kToStringOffset + kPointerSize
    kTypeOfOffset = kToNumberOffset + kPointerSize
    kKindOffset = kTypeOfOffset + kPointerSize
    kSize = kKindOffset + kPointerSize

    kFalse = 0
    kTrue = 1
    kNotBooleanMask = ~1
    kTheHole = 2
    kNull = 3
    kArgumentMarker = 4
    kUndefined = 5
    kUninitialized = 6
    kOther = 7
    kException = 8

    KIND_TO_NAME = ['kFalse',
                    'kTrue',
                    'kTheHole',
                    'kNull',
                    'kArgumentMarker',
                    'kUndefined',
                    'kUninitialized',
                    'kOther',
                    'kException']

    @staticmethod
    def get_to_string_addr(data):
        return get_dword(data, Oddball.kToStringOffset)

    @staticmethod
    def get_to_number_addr(data):
        return get_dword(data, Oddball.kToNumberOffset)

    @staticmethod
    def get_type_of_addr(data):
        return get_dword(data, Oddball.kTypeOfOffset)

    @staticmethod
    def get_kind(data):
        return get_dword_smi(data, Oddball.kKindOffset)

    @staticmethod
    def get_kind_name(data):
        kind_num = Oddball.get_kind(data)
        if kind_num < len(Oddball.KIND_TO_NAME):
            return Oddball.KIND_TO_NAME[kind_num]
        return 'Unknown'

    def do_parse(self):
        HeapObject.do_parse(self)
        self.append('kToStringAddr: 0x%x' % Oddball.get_to_string_addr(self.data))
        self.append('kToNumberAddr: 0x%x' % Oddball.get_to_number_addr(self.data))
        self.append('kTypeOfOffset: 0x%x' % Oddball.get_type_of_addr(self.data))
        self.append('kKind: 0x%x (%s)' % (Oddball.get_kind(self.data), Oddball.get_kind_name(self.data)))


class Cell(HeapObject):
    """
    class Cell: public HeapObject;
    """
    kValueOffset = HeapObject.kHeaderSize
    kSize = kValueOffset + kPointerSize

    @staticmethod
    def get_value_addr(data):
        return get_dword(data, Cell.kValueOffset)

    def do_parse(self):
        HeapObject.do_parse(self)
        self.append('kValueAddr: 0x%x' % Cell.get_value_addr(self.data))


class PropertyCell(HeapObject):
    """
    class PropertyCell : public HeapObject;
    """
    kDetailsOffset = HeapObject.kHeaderSize
    kValueOffset = kDetailsOffset + kPointerSize
    kDependentCodeOffset = kValueOffset + kPointerSize
    kSize = kDependentCodeOffset + kPointerSize
    kPointerFieldsBeginOffset = kValueOffset
    kPointerFieldsEndOffset = kSize

    @staticmethod
    def get_details_addr(data):
        return get_dword(data, PropertyCell.kDetailsOffset)

    @staticmethod
    def get_value_addr(data):
        return get_dword(data, PropertyCell.kValueOffset)

    @staticmethod
    def get_dependent_code_addr(data):
        return get_dword(data, PropertyCell.kDependentCodeOffset)

    def do_parse(self):
        HeapObject.do_parse(self)
        self.append('kDetailsAddr: 0x%x' % PropertyCell.get_details_addr(self.data))
        self.append('kValueAddr: 0x%x' % PropertyCell.get_value_addr(self.data))
        self.append('kDependentCodeAddr: 0x%x' % PropertyCell.get_dependent_code_addr(self.data))


class JSReceiver(HeapObject):
    """
    class JSReceiver: public HeapObject;
    JSReceiver includes types on which properties can be defined, i.e.,
    JSObject and JSProxy.
    """


class JSObject(JSReceiver):
    """
    class JSObject: public JSReceiver;
    The JSObject describes real heap allocated JavaScript objects with
    properties.
    Note that the map of JSObject changes during execution to enable inline
    caching.
    """
    kPropertiesOffset = HeapObject.kHeaderSize
    kElementsOffset = kPropertiesOffset + kPointerSize
    kHeaderSize = kElementsOffset + kPointerSize

    kSize = kHeaderSize  # for mem dump needed

    # Maximal number of elements (numbered 0 .. kMaxElementCount - 1).
    # Also maximal value of JSArray's length property.
    kMaxElementCount = 0xffffffff

    # Constants for heuristics controlling conversion of fast elements
    # to slow elements.

    # Maximal gap that can be introduced by adding an element beyond
    # the current elements length.
    kMaxGap = 1024

    # Maximal length of fast elements array that won't be checked for
    # being dense enough on expansion.
    kMaxUncheckedFastElementsLength = 5000

    # Same as above but for old arrays. This limit is more strict. We
    # don't want to be wasteful with long lived objects.
    kMaxUncheckedOldFastElementsLength = 500

    # This constant applies only to the initial map of "$Object" aka
    # "global.Object" and not to arbitrary other JSObject maps.
    kInitialGlobalObjectUnusedPropertiesCount = 4

    kMaxInstanceSize = 255 * kPointerSize
    # When extending the backing storage for property values, we increase
    # its size by more than the 1 entry necessary, so sequentially adding fields
    # to the same object requires fewer allocations and copies.
    kFieldsAdded = 3

    @staticmethod
    def get_properties(data):
        return get_dword(data, JSObject.kPropertiesOffset)

    @staticmethod
    def get_elements_addr(data):
        return get_dword(data, JSObject.kElementsOffset)

    @staticmethod
    def get_internal_field_count(data):
        """
        Copy and modify from JSObject::GetInternalFieldCount(Map* map)
        Args:
            data: header data (str)

        Returns: Internal field count (int)

        """
        # Make sure to adjust for the number of in-object properties. These
        # properties do contribute to the size, but are not internal fields.
        size = HeapObject.get_object_size(data)
        map_addr = HeapObject.get_map_addr(data)
        map_object = Map(Handle(map_addr))
        in_object_properties = map_object.get_in_object_properties_or_constructor_function_index(map_object.data)
        return ((size - JSObject.get_header_size(data)) >> kPointerSizeLog2) - in_object_properties

    @staticmethod
    def get_header_size(data):
        """
        Copy and modify from JSObject::GetHeaderSize(InstanceType type)
        Args:
            data: header data (str)

        Returns: header size (int)

        """
        map_addr = HeapObject.get_map_addr(data)
        map_object = Map(Handle(map_addr))
        instance_type = map_object.get_instance_type(map_object.data)
        if instance_type == InstanceType.JS_OBJECT_TYPE:
            return JSObject.kHeaderSize
        # TYPES = {InstanceType.JS_GENERATOR_OBJECT_TYPE: JSGeneratorObject.kSize,
        #          InstanceType.JS_MODULE_TYPE: JSModule.kSize,
        #          InstanceType.JS_GLOBAL_PROXY_TYPE: JSGlobalProxy.kSize,
        #          InstanceType.JS_GLOBAL_OBJECT_TYPE: JSGlobalObject.kSize,
        #          InstanceType.JS_BUILTINS_OBJECT_TYPE: JSBuiltinsObject.kSize,
        #          InstanceType.JS_FUNCTION_TYPE: JSFunction.kSize,
        #          InstanceType.JS_VALUE_TYPE: JSValue.kSize,
        #          InstanceType.JS_DATE_TYPE: JSDate.kSize,
        #          InstanceType.JS_ARRAY_TYPE: JSArray.kSize,
        #          InstanceType.JS_ARRAY_BUFFER_TYPE: JSArrayBuffer.kSize,
        #          InstanceType.JS_TYPED_ARRAY_TYPE: JSTypedArray.kSize,
        #          InstanceType.JS_DATA_VIEW_TYPE: JSDataView.kSize,
        #          InstanceType.JS_SET_TYPE: JSSet.kSize,
        #          InstanceType.JS_MAP_TYPE: JSMap.kSize,
        #          InstanceType.JS_SET_ITERATOR_TYPE: JSSetIterator.kSize,
        #          InstanceType.JS_MAP_ITERATOR_TYPE: JSMapIterator.kSize,
        #          InstanceType.JS_WEAK_MAP_TYPE: JSWeakMap.kSize,
        #          InstanceType.JS_WEAK_SET_TYPE: JSWeakSet.kSize,
        #          InstanceType.JS_REGEXP_TYPE: JSRegExp.kSize,
        #          InstanceType.JS_CONTEXT_EXTENSION_OBJECT_TYPE: JSObject.kHeaderSize,
        #          InstanceType.JS_MESSAGE_OBJECT_TYPE: JSMessageObject.kSize}

        # TODO: this is a temp solution
        if instance_type == InstanceType.JS_GLOBAL_PROXY_TYPE:
            return JSGlobalProxy.kSize
        if instance_type == InstanceType.JS_GLOBAL_OBJECT_TYPE:
            return JSGlobalObject.kSize
        if instance_type == InstanceType.JS_FUNCTION_TYPE:
            return JSFunction.kSize
        if instance_type == InstanceType.JS_VALUE_TYPE:
            return JSValue.kSize
        if instance_type == InstanceType.JS_ARRAY_TYPE:
            return JSArray.kSize
        if instance_type == InstanceType.JS_ARRAY_BUFFER_TYPE:
            return JSArrayBuffer.kSize
        if instance_type == InstanceType.JS_TYPED_ARRAY_TYPE:
            return JSTypedArray.kSize
        if instance_type == InstanceType.JS_DATA_VIEW_TYPE:
            return JSDataView.kSize
        if instance_type == InstanceType.JS_CONTEXT_EXTENSION_OBJECT_TYPE:
            return JSObject.kHeaderSize
        return 0

    def get_internal_fields(self):
        field_count = JSObject.get_internal_field_count(self.data)
        self.increase_size(field_count * kPointerSize)
        return to_dword(read(self.data, JSObject.get_header_size(self.data), field_count * kPointerSize), False)

    def get_in_object_properties(self):
        """
        Get InObjectProperties
        Returns: [str]

        """
        size = HeapObject.get_object_size(self.data)
        self.update_size(size)
        map_addr = HeapObject.get_map_addr(self.data)
        map_object = Map(Handle(map_addr))
        in_object_properties_count = Map.get_in_object_properties_or_constructor_function_index(map_object.data)
        instance_size = Map.get_instance_size(map_object.data)
        # TODO: Handle UnboxedDoubleFields. Note that followed operation may fail
        properties = to_dword(read(self.data, instance_size - in_object_properties_count * kPointerSize,
                                   in_object_properties_count * kPointerSize), False)
        return [str(smi_to_int(i)) if has_smi_tag(i) else '0x%x' % i for i in properties]

    def parse(self):
        """
        Add JSObject InternalFields support.
        Returns: parse result (list)

        """
        self.do_parse()

        internal_fields = ['%d:\t0x%x' % (index, value) for index, value in
                           enumerate(self.get_internal_fields())]
        field_count = len(internal_fields)
        internal_fields_str = '\n\t' * (field_count != 0) + '\n\t'.join(internal_fields)
        self.append('InternalFields (Count: %d, Size: 0x%x)%s' %
                    (field_count, field_count * kPointerSize, internal_fields_str))

        in_object_properties = ['%d:\t%s' % (index, value) for index, value in
                                enumerate(self.get_in_object_properties())]
        in_object_properties_count = len(in_object_properties)
        in_object_properties_str = '\n\t' * (in_object_properties_count != 0) + '\n\t'.join(in_object_properties)
        self.append('InObjectProperties (Count: %d, Size: 0x%x)%s' %
                    (in_object_properties_count, in_object_properties_count * kPointerSize, in_object_properties_str))

        return self.result

    def do_parse(self):
        JSReceiver.do_parse(self)
        self.append('kProperties: 0x%x' % JSObject.get_properties(self.data))
        self.append('kElementsAddr: 0x%x' % JSObject.get_elements_addr(self.data))


class JSFunction(JSObject):
    """
    class JSFunction: public JSObject;
    JSFunction describes JavaScript functions.
    """
    kPrototypeOrInitialMapOffset = JSObject.kHeaderSize
    kSharedFunctionInfoOffset = kPrototypeOrInitialMapOffset + kPointerSize
    kContextOffset = kSharedFunctionInfoOffset + kPointerSize
    kLiteralsOffset = kContextOffset + kPointerSize
    kNonWeakFieldsEndOffset = kLiteralsOffset + kPointerSize
    kCodeEntryOffset = kNonWeakFieldsEndOffset
    kNextFunctionLinkOffset = kCodeEntryOffset + kPointerSize
    kSize = kNextFunctionLinkOffset + kPointerSize

    @staticmethod
    def get_prototype_or_initial_map_addr(data):
        return get_dword(data, JSFunction.kPrototypeOrInitialMapOffset)

    @staticmethod
    def get_shared_function_info_addr(data):
        return get_dword(data, JSFunction.kSharedFunctionInfoOffset)

    @staticmethod
    def get_context_addr(data):
        return get_dword(data, JSFunction.kContextOffset)

    @staticmethod
    def get_literals_addr(data):
        return get_dword(data, JSFunction.kLiteralsOffset)

    @staticmethod
    def get_non_weak_fields_end_addr(data):
        return get_dword(data, JSFunction.kNonWeakFieldsEndOffset)

    @staticmethod
    def get_code_entry_addr(data):
        return get_dword(data, JSFunction.kCodeEntryOffset)

    @staticmethod
    def get_next_function_link_addr(data):
        return get_dword(data, JSFunction.kNextFunctionLinkOffset)

    def do_parse(self):
        JSObject.do_parse(self)
        self.append('kPrototypeOrInitialMapAddr: 0x%x' % JSFunction.get_prototype_or_initial_map_addr(self.data))
        self.append('kSharedFunctionInfoAddr: 0x%x' % JSFunction.get_shared_function_info_addr(self.data))
        self.append('kContextAddr: 0x%x' % JSFunction.get_context_addr(self.data))
        self.append('kLiteralsAddr: 0x%x' % JSFunction.get_literals_addr(self.data))
        self.append('kNonWeakFieldsEndAddr: 0x%x' % JSFunction.get_non_weak_fields_end_addr(self.data))
        self.append('\tkCodeEntryAddr: 0x%x' % JSFunction.get_code_entry_addr(self.data))
        self.append('kNextFunctionLinkAddr: 0x%x' % JSFunction.get_next_function_link_addr(self.data))


class JSGlobalProxy(JSObject):
    """
    class JSGlobalProxy : public JSObject;
    JSGlobalProxy's prototype must be a JSGlobalObject or null,
    and the prototype is hidden. JSGlobalProxy always delegates
    property accesses to its prototype if the prototype is not null.

    A JSGlobalProxy can be reinitialized which will preserve its identity.

    Accessing a JSGlobalProxy requires security check.
    """
    kNativeContextOffset = JSObject.kHeaderSize
    kHashOffset = kNativeContextOffset + kPointerSize
    kSize = kHashOffset + kPointerSize

    @staticmethod
    def get_native_context_addr(data):
        return get_dword(data, JSGlobalProxy.kNativeContextOffset)

    @staticmethod
    def get_hash_addr(data):
        return get_dword(data, JSGlobalProxy.kHashOffset)

    def do_parse(self):
        JSObject.do_parse(self)
        self.append('kNativeContextAddr: 0x%x' % JSGlobalProxy.get_native_context_addr(self.data))
        self.append('kHashAddr: 0x%x' % JSGlobalProxy.get_hash_addr(self.data))


class JSGlobalObject(JSObject):
    """
    class JSGlobalObject : public JSObject;
    JavaScript global object.
    """
    kNativeContextOffset = JSObject.kHeaderSize
    kGlobalProxyOffset = kNativeContextOffset + kPointerSize
    kHeaderSize = kGlobalProxyOffset + kPointerSize
    kSize = kHeaderSize

    @staticmethod
    def get_native_context_addr(data):
        return get_dword(data, JSGlobalObject.kNativeContextOffset)

    @staticmethod
    def get_global_proxy_addr(data):
        return get_dword(data, JSGlobalObject.kGlobalProxyOffset)

    def do_parse(self):
        JSObject.do_parse(self)
        self.append('kNativeContextAddr: 0x%x' % JSGlobalObject.get_native_context_addr(self.data))
        self.append('kGlobalProxyAddr: 0x%x' % JSGlobalObject.get_global_proxy_addr(self.data))


class JSValue(JSObject):
    """
    class JSValue: public JSObject;
    Representation for JS Wrapper objects, String, Number, Boolean, etc.
    """
    kValueOffset = JSObject.kHeaderSize
    kSize = kValueOffset + kPointerSize

    @staticmethod
    def get_value_addr(data):
        return get_dword(data, JSValue.kValueOffset)

    def do_parse(self):
        JSObject.do_parse(self)
        self.append('kValueAddr: 0x%x' % JSValue.get_value_addr(self.data))


class JSCollection(JSObject):
    """
    class JSCollection : public JSObject;
    """
    kTableOffset = JSObject.kHeaderSize
    kSize = kTableOffset + kPointerSize

    @staticmethod
    def get_table_addr(data):
        return get_dword(data, JSCollection.kTableOffset)

    def do_parse(self):
        JSObject.do_parse(self)
        self.append('kTableAddr: 0x%x' % JSCollection.get_table_addr(self.data))


class JSSet(JSCollection):
    """
    class JSSet : public JSCollection;
    The JSSet describes EcmaScript Harmony sets
    """


class JSMap(JSCollection):
    """
    class JSMap : public JSCollection;
    The JSMap describes EcmaScript Harmony maps
    """


class JSWeakCollection(JSObject):
    """
    class JSWeakCollection: public JSObject;
    Base class for both JSWeakMap and JSWeakSet
    """
    kTableOffset = JSObject.kHeaderSize
    kNextOffset = kTableOffset + kPointerSize
    kSize = kNextOffset + kPointerSize

    @staticmethod
    def get_table_addr(data):
        return get_dword(data, JSWeakCollection.kTableOffset)

    @staticmethod
    def get_next_addr(data):
        return get_dword(data, JSWeakCollection.kNextOffset)

    def do_parse(self):
        JSObject.do_parse(self)
        self.append('kTableAddr: 0x%x' % JSWeakCollection.get_table_addr(self.data))
        self.append('kNextAddr: 0x%x' % JSWeakCollection.get_next_addr(self.data))


class JSWeakMap(JSWeakCollection):
    """
    class JSWeakMap: public JSWeakCollection;
    The JSWeakMap describes EcmaScript Harmony weak maps
    """


class JSWeakSet(JSWeakCollection):
    """
    class JSWeakSet: public JSWeakCollection;
    The JSWeakSet describes EcmaScript Harmony weak sets
    """


class JSArrayBuffer(JSObject):
    """
    class JSArrayBuffer: public JSObject;
    """
    kByteLengthOffset = JSObject.kHeaderSize
    # NOTE: GC will visit objects fields:
    # 1. From JSObject::BodyDescriptor::kStartOffset to kByteLengthOffset +
    #    kPointerSize
    # 2. From start of the internal fields and up to the end of them
    kBackingStoreOffset = kByteLengthOffset + kPointerSize
    kBitFieldSlot = kBackingStoreOffset + kPointerSize
    kBitFieldOffset = kBitFieldSlot
    kSize = kBitFieldSlot + kPointerSize

    kSizeWithInternalFields = kSize + kInternalFieldCount * kPointerSize

    @staticmethod
    def get_backing_store_addr(data):
        return get_dword(data, JSArrayBuffer.kBackingStoreOffset)

    @staticmethod
    def get_byte_length(data):
        return get_dword_smi(data, JSArrayBuffer.kByteLengthOffset)

    @staticmethod
    def get_bit_field(data):
        return get_dword(data, JSArrayBuffer.kBitFieldOffset)

    @staticmethod
    @BitField(1)
    def is_external(data):
        return JSArrayBuffer.get_bit_field(data)

    @staticmethod
    @BitField(2)
    def is_neuterable(data):
        return JSArrayBuffer.get_bit_field(data)

    @staticmethod
    @BitField(3)
    def was_neutered(data):
        return JSArrayBuffer.get_bit_field(data)

    @staticmethod
    @BitField(4)
    def is_shared(data):
        return JSArrayBuffer.get_bit_field(data)

    def do_parse(self):
        JSObject.do_parse(self)
        self.append('kByteLength: 0x%x' % JSArrayBuffer.get_byte_length(self.data))
        self.append('kBackingStoreAddr: 0x%x' % JSArrayBuffer.get_backing_store_addr(self.data))
        self.append('kBitField: 0x%x'
                    '\n\tIsExternal: 0x%x'
                    '\n\tIsNeuterable: 0x%x'
                    '\n\tWasNeutered: 0x%x'
                    '\n\tIsShared: 0x%x' %
                    (JSArrayBuffer.get_bit_field(self.data),
                     JSArrayBuffer.is_external(self.data),
                     JSArrayBuffer.is_neuterable(self.data),
                     JSArrayBuffer.was_neutered(self.data),
                     JSArrayBuffer.is_shared(self.data),))


class JSArrayBufferView(JSObject):
    """
    class JSArrayBufferView: public JSObject;
    """
    kBufferOffset = JSObject.kHeaderSize
    kByteOffsetOffset = kBufferOffset + kPointerSize
    kByteLengthOffset = kByteOffsetOffset + kPointerSize
    kViewSize = kByteLengthOffset + kPointerSize

    kSize = kViewSize  # for mem dump

    @staticmethod
    def get_buffer_addr(data):
        return get_dword(data, JSArrayBufferView.kBufferOffset)

    @staticmethod
    def get_byte_offset_addr(data):
        return get_dword(data, JSArrayBufferView.kByteOffsetOffset)

    @staticmethod
    def get_byte_length_addr(data):
        return get_dword(data, JSArrayBufferView.kByteLengthOffset)

    def do_parse(self):
        JSObject.do_parse(self)
        self.append('kBufferAddr: 0x%x' % JSArrayBufferView.get_buffer_addr(self.data))
        self.append('kByteOffsetAddr: 0x%x' % JSArrayBufferView.get_byte_offset_addr(self.data))
        self.append('kByteLengthAddr: 0x%x' % JSArrayBufferView.get_byte_length_addr(self.data))


class JSTypedArray(JSArrayBufferView):
    """
    class JSTypedArray: public JSArrayBufferView;
    """
    kLengthOffset = JSArrayBufferView.kViewSize + kPointerSize
    kSize = kLengthOffset + kPointerSize
    kSizeWithInternalFields = kSize + kInternalFieldCount * kPointerSize

    @staticmethod
    def get_length_addr(data):
        return get_dword(data, JSTypedArray.kLengthOffset)

    def do_parse(self):
        JSArrayBufferView.do_parse(self)
        self.append('kLengthAddr: 0x%x' % JSTypedArray.get_length_addr(self.data))


class JSDataView(JSArrayBufferView):
    """
    class JSDataView: public JSArrayBufferView;
    """
    kSize = JSArrayBufferView.kViewSize
    kSizeWithInternalFields = kSize + kInternalFieldCount * kPointerSize


class JSArray(JSObject):
    """
    class JSArray: public JSObject;
    The JSArray describes JavaScript Arrays
     Such an array can be in one of two modes:
       - fast, backing storage is a FixedArray and length <= elements.length()
          Please note: push and pop can be used to grow and shrink the array.
       - slow, backing storage is a HashTable with numbers as keys.
    """
    kLengthOffset = JSObject.kHeaderSize
    kSize = kLengthOffset + kPointerSize

    # Number of element slots to pre-allocate for an empty array.
    kPreallocatedArrayElements = 4

    # # 600 * KB is the Page::kMaxRegularHeapObjectSize defined in spaces.h which
    # # we do not want to include in objects.h
    # # Note that Page::kMaxRegularHeapObjectSize has to be in sync with
    # # kInitialMaxFastElementArray which is checked in a DCHECK in heap.cc.
    # kInitialMaxFastElementArray = (600 * KB - FixedArray.kHeaderSize - kSize - AllocationMemento.kSize) // kPointerSize

    @staticmethod
    def get_length(data):
        return get_dword_smi(data, JSArray.kLengthOffset)

    def do_parse(self):
        JSObject.do_parse(self)
        self.append('kLength: 0x%x' % JSArray.get_length(self.data))


class Struct(HeapObject):
    """
    class Struct: public HeapObject;
    An abstract superclass, a marker class really, for simple structure classes.
    It doesn't carry much functionality but allows struct classes to be
    identified in the type system.
    """


class AllocationMemento(Struct):
    """
    class AllocationMemento: public Struct;
    """
    kAllocationSiteOffset = HeapObject.kHeaderSize
    kSize = kAllocationSiteOffset + kPointerSize

    @staticmethod
    def get_allocation_site_addr(data):
        return get_dword(data, AllocationMemento.kAllocationSiteOffset)

    def do_parse(self):
        Struct.do_parse(self)
        self.append('kAllocationSiteAddr: 0x%x' % AllocationMemento.get_allocation_site_addr(self.data))


class AccessorInfo(Struct):
    """
    class AccessorInfo: public Struct;
    """
    kNameOffset = HeapObject.kHeaderSize
    kFlagOffset = kNameOffset + kPointerSize
    kExpectedReceiverTypeOffset = kFlagOffset + kPointerSize
    kSize = kExpectedReceiverTypeOffset + kPointerSize

    # Bit positions in flag.
    kAllCanReadBit = 0
    kAllCanWriteBit = 1
    kSpecialDataProperty = 2

    #   class AttributesField : public BitField<PropertyAttributes, 3, 3> {};

    @staticmethod
    def get_name_addr(data):
        return get_dword(data, AccessorInfo.kNameOffset)

    @staticmethod
    def get_flag_addr(data):
        return get_dword(data, AccessorInfo.kFlagOffset)

    @staticmethod
    def get_expected_receiver_type(data):
        return get_dword(data, AccessorInfo.kExpectedReceiverTypeOffset)

    def do_parse(self):
        Struct.do_parse(self)
        self.append('kNameAddr: 0x%x' % AccessorInfo.get_name_addr(self.data))
        self.append('kFlagAddr: 0x%x' % AccessorInfo.get_flag_addr(self.data))
        self.append('kExpectedReceiverTypeAddr: 0x%x' % AccessorInfo.get_expected_receiver_type(self.data))


class ExecutableAccessorInfo(AccessorInfo):
    """
    class ExecutableAccessorInfo: public AccessorInfo;
    An accessor must have a getter, but can have no setter.
    When setting a property, V8 searches accessors in prototypes.
    If an accessor was found and it does not have a setter,
    the request is ignored.
    If the accessor in the prototype has the READ_ONLY property attribute, then
    a new value is added to the derived object when the property is set.
    This shadows the accessor in the prototype.
    """
    kGetterOffset = AccessorInfo.kSize
    kSetterOffset = kGetterOffset + kPointerSize
    kDataOffset = kSetterOffset + kPointerSize
    kSize = kDataOffset + kPointerSize

    @staticmethod
    def get_getter_addr(data):
        return get_dword(data, ExecutableAccessorInfo.kGetterOffset)

    @staticmethod
    def get_setter_addr(data):
        return get_dword(data, ExecutableAccessorInfo.kSetterOffset)

    @staticmethod
    def get_data_addr(data):
        return get_dword(data, ExecutableAccessorInfo.kDataOffset)

    def do_parse(self):
        AccessorInfo.do_parse(self)
        self.append('kGetterAddr: 0x%x' % ExecutableAccessorInfo.get_getter_addr(self.data))
        self.append('kSetterAddr: 0x%x' % ExecutableAccessorInfo.get_setter_addr(self.data))
        self.append('kDataAddr: 0x%x' % ExecutableAccessorInfo.get_data_addr(self.data))


class AccessorPair(Struct):
    """
    class AccessorPair: public Struct;
    Support for JavaScript accessors: A pair of a getter and a setter. Each
    accessor can either be
      * a pointer to a JavaScript function or proxy: a real accessor
      * undefined: considered an accessor by the spec, too, strangely enough
      * the hole: an accessor which has not been set
      * a pointer to a map: a transition used to ensure map sharing
    """
    kGetterOffset = HeapObject.kHeaderSize
    kSetterOffset = kGetterOffset + kPointerSize
    kSize = kSetterOffset + kPointerSize

    @staticmethod
    def get_getter_addr(data):
        return get_dword(data, AccessorPair.kGetterOffset)

    @staticmethod
    def get_setter_addr(data):
        return get_dword(data, AccessorPair.kSetterOffset)

    def do_parse(self):
        Struct.do_parse(self)
        self.append('kGetterAddr: 0x%x' % AccessorPair.get_getter_addr(self.data))
        self.append('kSetterAddr: 0x%x' % AccessorPair.get_setter_addr(self.data))


class TemplateInfo(Struct):
    """
    class TemplateInfo: public Struct;
    """
    kTagOffset = HeapObject.kHeaderSize
    kNumberOfProperties = kTagOffset + kPointerSize
    kPropertyListOffset = kNumberOfProperties + kPointerSize
    kPropertyAccessorsOffset = kPropertyListOffset + kPointerSize
    kPropertyIntrinsicsOffset = kPropertyAccessorsOffset + kPointerSize
    kHeaderSize = kPropertyIntrinsicsOffset + kPointerSize
    kSize = kHeaderSize  # for mem dump needed

    @staticmethod
    def get_tag_addr(data):
        return get_dword(data, TemplateInfo.kTagOffset)

    @staticmethod
    def get_property_list_addr(data):
        return get_dword(data, TemplateInfo.kPropertyListOffset)

    @staticmethod
    def get_property_accessors_addr(data):
        return get_dword(data, TemplateInfo.kPropertyAccessorsOffset)

    @staticmethod
    def get_property_intrinsics_addr(data):
        return get_dword(data, TemplateInfo.kPropertyIntrinsicsOffset)

    def do_parse(self):
        Struct.do_parse(self)
        self.append('kTagAddr: 0x%x' % TemplateInfo.get_tag_addr(self.data))
        self.append('kPropertyListAddr: 0x%x' % TemplateInfo.get_property_list_addr(self.data))
        self.append('kPropertyAccessorsAddr: 0x%x' % TemplateInfo.get_property_accessors_addr(self.data))
        self.append('kPropertyIntrinsicsAddr: 0x%x' % TemplateInfo.get_property_intrinsics_addr(self.data))


class FunctionTemplateInfo(TemplateInfo):
    """
    class FunctionTemplateInfo: public TemplateInfo;
    """
    kSerialNumberOffset = TemplateInfo.kHeaderSize
    kCallCodeOffset = kSerialNumberOffset + kPointerSize
    kPrototypeTemplateOffset = kCallCodeOffset + kPointerSize
    kParentTemplateOffset = kPrototypeTemplateOffset + kPointerSize
    kNamedPropertyHandlerOffset = kParentTemplateOffset + kPointerSize
    kIndexedPropertyHandlerOffset = kNamedPropertyHandlerOffset + kPointerSize
    kInstanceTemplateOffset = kIndexedPropertyHandlerOffset + kPointerSize
    kClassNameOffset = kInstanceTemplateOffset + kPointerSize
    kSignatureOffset = kClassNameOffset + kPointerSize
    kInstanceCallHandlerOffset = kSignatureOffset + kPointerSize
    kAccessCheckInfoOffset = kInstanceCallHandlerOffset + kPointerSize
    kFlagOffset = kAccessCheckInfoOffset + kPointerSize
    kLengthOffset = kFlagOffset + kPointerSize
    kSize = kLengthOffset + kPointerSize

    kHiddenPrototypeBit = 0
    kUndetectableBit = 1
    kNeedsAccessCheckBit = 2
    kReadOnlyPrototypeBit = 3
    kRemovePrototypeBit = 4
    kDoNotCacheBit = 5
    kInstantiatedBit = 6
    kAcceptAnyReceiver = 7

    @staticmethod
    def get_serial_number_addr(data):
        return get_dword(data, FunctionTemplateInfo.kSerialNumberOffset)

    @staticmethod
    def get_call_code_addr(data):
        return get_dword(data, FunctionTemplateInfo.kCallCodeOffset)

    @staticmethod
    def get_prototype_template_addr(data):
        return get_dword(data, FunctionTemplateInfo.kPrototypeTemplateOffset)

    @staticmethod
    def get_parent_template_addr(data):
        return get_dword(data, FunctionTemplateInfo.kParentTemplateOffset)

    @staticmethod
    def get_named_property_handler_addr(data):
        return get_dword(data, FunctionTemplateInfo.kNamedPropertyHandlerOffset)

    @staticmethod
    def get_indexed_property_handler_addr(data):
        return get_dword(data, FunctionTemplateInfo.kIndexedPropertyHandlerOffset)

    @staticmethod
    def get_instance_template_addr(data):
        return get_dword(data, FunctionTemplateInfo.kInstanceTemplateOffset)

    @staticmethod
    def get_class_name_addr(data):
        return get_dword(data, FunctionTemplateInfo.kClassNameOffset)

    @staticmethod
    def get_signature_addr(data):
        return get_dword(data, FunctionTemplateInfo.kSignatureOffset)

    @staticmethod
    def get_instance_call_handler_addr(data):
        return get_dword(data, FunctionTemplateInfo.kInstanceCallHandlerOffset)

    @staticmethod
    def get_access_check_info_addr(data):
        return get_dword(data, FunctionTemplateInfo.kAccessCheckInfoOffset)

    @staticmethod
    def get_flag(data):
        return get_dword_smi(data, FunctionTemplateInfo.kFlagOffset)

    @staticmethod
    def get_length(data):
        return get_dword_smi(data, FunctionTemplateInfo.kLengthOffset)

    def do_parse(self):
        TemplateInfo.do_parse(self)
        self.append('kSerialNumberAddr: 0x%x' % FunctionTemplateInfo.get_serial_number_addr(self.data))
        self.append('kCallCodeAddr: 0x%x' % FunctionTemplateInfo.get_call_code_addr(self.data))
        self.append('kPrototypeTemplateAddr: 0x%x' % FunctionTemplateInfo.get_prototype_template_addr(self.data))
        self.append('kParentTemplateAddr: 0x%x' % FunctionTemplateInfo.get_parent_template_addr(self.data))
        self.append('kNamedPropertyHandlerAddr: 0x%x' % FunctionTemplateInfo.get_named_property_handler_addr(self.data))
        self.append(
            'kIndexedPropertyHandlerAddr: 0x%x' % FunctionTemplateInfo.get_indexed_property_handler_addr(self.data))
        self.append('kInstanceTemplateAddr: 0x%x' % FunctionTemplateInfo.get_instance_template_addr(self.data))
        self.append('kClassNameAddr: 0x%x' % FunctionTemplateInfo.get_class_name_addr(self.data))
        self.append('kSignatureAddr: 0x%x' % FunctionTemplateInfo.get_signature_addr(self.data))
        self.append('kInstanceCallHandlerAddr: 0x%x' % FunctionTemplateInfo.get_instance_call_handler_addr(self.data))
        self.append('kAccessCheckInfoAddr: 0x%x' % FunctionTemplateInfo.get_access_check_info_addr(self.data))
        self.append('kFlag: 0x%x' % FunctionTemplateInfo.get_flag(self.data))
        self.append('kLength: 0x%x' % FunctionTemplateInfo.get_length(self.data))


class ObjectTemplateInfo(TemplateInfo):
    """
    class ObjectTemplateInfo: public TemplateInfo;
    """
    kConstructorOffset = TemplateInfo.kHeaderSize
    kInternalFieldCountOffset = kConstructorOffset + kPointerSize
    kSize = kInternalFieldCountOffset + kPointerSize

    @staticmethod
    def get_constructor_addr(data):
        return get_dword(data, ObjectTemplateInfo.kConstructorOffset)

    @staticmethod
    def get_internal_field_count_addr(data):
        return get_dword(data, ObjectTemplateInfo.kInternalFieldCountOffset)

    def do_parse(self):
        TemplateInfo.do_parse(self)
        self.append('kConstructorAddr: 0x%x' % ObjectTemplateInfo.get_constructor_addr(self.data))
        self.append('kInternalFieldCountAddr: 0x%x' % ObjectTemplateInfo.get_internal_field_count_addr(self.data))


######################################################################################
#                                     Handle                                         #
######################################################################################

# Equal to *handle.location_
class Handle:
    def __init__(self, location_, type_=None):
        self._location = location_
        self._type = type_
        self._class = None
        if self._type is not None:
            self._class = Map.type_to_class(self._type)

    def is_smi(self):
        return has_smi_tag(self._location)

    def is_failure(self):
        return has_failure_tag(self._location)

    def is_heap_object(self):
        return not self.is_failure() and has_heap_object_tag(self._location)

    def decode(self, bitness=32):
        if self.is_smi():
            smi_to_int(self._location, bitness)
        elif self.is_failure():
            return 0
        elif self.is_heap_object():
            return raw_heap_object(self._location)
        else:
            return 0

    def get_class(self):
        """
        Get stored class
        Returns: class (Object)

        """
        return self._class

    def data(self, size=kPointerSize):
        """
        Smartly read data
        Args:
            size: read size (int)

        Returns: data (str). Invalid address returns ''.

        """
        # Double Check
        location = raw_heap_object(self._location) if self.is_heap_object() else self._location
        data = read_mem(location, size)
        if not data:
            warn_log = "Cannot access memory at address 0x%x" % location
            warning(warn_log)
        return data

    def get_instance_type(self):
        """
        Get Handle's instanceType
        Returns: type num (int)

        """
        map_data = self.data(kPointerSize)
        if not map_data:
            return None
        map_handle = Handle(HeapObject.get_map_addr(map_data))
        if not map_handle.is_heap_object():
            return None
        map_map_data = map_handle.data(Map.kSize)
        if not map_map_data:
            return None
        return Map.get_instance_type(map_map_data)

    def parse(self, bitness=32):
        """
        Auto parse the Handle
        Args:
            bitness: arch bitness (int)

        Returns: parse result (int / list)

        """
        if self._type is not None and self._class is not None and Map.type_to_class(self._type) != self._class:
            self._type = self._class = None
        if self._type is None:
            if self.is_smi():
                return smi_to_int(self._location, bitness)
            elif self.is_failure():
                return ['Has failure tag. Maybe Failure Object?']
            elif self.is_heap_object():
                self._type = self.get_instance_type()
        if self._type is None:
            warning('Handle points to an invalid Map!')
            return None
        if self._class is None:
            self._class = Map.type_to_class(self._type)
        if self._class is not None:
            c = self._class(self)
            try:
                result = c.parse()
                result.insert(0, 'DESCRIPTION:%s' % self._class.__doc__)
                result.insert(0, 'Heap Pointer: 0x%x' % self.decode())
                return result
            except Exception as e:
                if config.Option.get("debug") == "on":
                    msg("Exception: %s" % e)
                    traceback.print_exc()
                warning('Parse 0x%x failed' % self._location)
        return None


######################################################################################
#                          elements kind auto setup                                  #
######################################################################################

ELEMENTS_KIND_TO_NAME = {}


def get_elements_kind_name(kind_num):
    if not kind_num in ELEMENTS_KIND_TO_NAME:
        return ''
    return ', '.join(ELEMENTS_KIND_TO_NAME.get(kind_num))


def init_elements_kind_to_name():
    for name_str in dir(ElementsKind):
        if name_str.startswith('_'):
            continue
        global ELEMENTS_KIND_TO_NAME
        type_num = getattr(ElementsKind, name_str)
        if type_num not in ELEMENTS_KIND_TO_NAME:
            ELEMENTS_KIND_TO_NAME[type_num] = [name_str]
        else:
            ELEMENTS_KIND_TO_NAME.get(type_num).append(name_str)


init_elements_kind_to_name()

######################################################################################
#                          instance type auto setup                                  #
######################################################################################

# { int => list }
TYPE_TO_NAME = {}


def get_instance_type_name(type_num):
    if not type_num in TYPE_TO_NAME:
        return ''
    return ', '.join(TYPE_TO_NAME.get(type_num))


def init_type_to_name():
    for instance_type_name in dir(InstanceType):
        if not instance_type_name.endswith('_TYPE'):
            continue
        global TYPE_TO_NAME
        type_num = getattr(InstanceType, instance_type_name)
        if type_num not in TYPE_TO_NAME:
            TYPE_TO_NAME[type_num] = [instance_type_name]
        else:
            TYPE_TO_NAME.get(type_num).append(instance_type_name)


init_type_to_name()

# { int => class }
TYPE_TO_CLASS = {}


def is_v8_class(c):
    if not isinstance(c, type(Object)):
        return False
    if c is Object:
        return True
    base = c.__bases__
    if base:
        if base[0] is Object:
            return True
        else:
            return is_v8_class(base[0])
    else:
        return False


def add_type_to_class(instance_type_name_or_num, class_type):
    if not is_v8_class(class_type):
        return
    if isinstance(instance_type_name_or_num, int):
        type_num = instance_type_name_or_num
        instance_type_name = get_instance_type_name(type_num)
    else:
        instance_type_name = instance_type_name_or_num
        type_num = getattr(InstanceType, instance_type_name)
    global TYPE_TO_CLASS
    if type_num not in TYPE_TO_CLASS:
        TYPE_TO_CLASS[type_num] = class_type
        info('Registering type %s' % instance_type_name)


def init_type_to_class():
    this_module = sys.modules[__name__]
    for instance_type_name in dir(InstanceType):
        s = instance_type_name
        if not s.endswith('_TYPE'):
            continue
        s = s[:-5]
        class_name = []
        need_upper = True
        for index, value in enumerate(s):
            if index == 0 and value == 'J' or index == 1 and value == 'S':
                class_name.append(value)
                continue
            if value == '_':
                need_upper = True
                continue
            if need_upper:
                class_name.append(value.upper())
                need_upper = False
            else:
                class_name.append(value.lower())
        class_name = ''.join(class_name)
        if hasattr(this_module, class_name):
            add_type_to_class(instance_type_name, getattr(this_module, class_name))


init_type_to_class()
# manual add
add_type_to_class(InstanceType.ONE_BYTE_STRING_TYPE, SeqOneByteString)
add_type_to_class(InstanceType.ONE_BYTE_INTERNALIZED_STRING_TYPE, SeqOneByteString)
add_type_to_class(InstanceType.CONS_ONE_BYTE_STRING_TYPE, ConsString)

######################################################################################
#                                     invoke                                         #
######################################################################################

peda = None

# for opt
NAME_TO_TYPE = {
    'array': InstanceType.JS_ARRAY_TYPE,
    'object': InstanceType.JS_OBJECT_TYPE,
    'arraybuffer': InstanceType.JS_ARRAY_BUFFER_TYPE,
    'map': InstanceType.MAP_TYPE
}


def invoke(peda_, *arg):
    """
    Google v8 debug helper
    Usage:
        v8 [type] [addr]
    """
    global peda
    peda = peda_
    (opt, addr) = normalize_argv(arg, 2)

    type_name = NAME_TO_TYPE.get(opt)

    # support opt as 'handle'
    if type_name is None and opt == 'handle':
        type_name = -1

    if opt is None or type_name is not None and addr is None:
        try:
            v = peda.parse_and_eval('$')
        except:
            warning('gdb history is empty')
            return
    elif type_name is not None and addr is not None:
        v = addr
    else:
        v = opt

    a = to_int(v)

    # support opt as 'handle
    if type_name == -1 and a is not None:
        a = get_dword(read_mem(a))
        type_name = None

    if a is None:
        warning('Invalid arguments')
        return

    h = Handle(a, type_name)
    result = h.parse()

    if result is not None:
        if isinstance(result, int):
            msg('SMI: %d' % result)
        elif isinstance(result, list):
            msg('\n'.join(result))
        else:
            msg(result)
    else:
        warning('Cannot decode this value.')


invoke.options = list(NAME_TO_TYPE.keys()) + ['handle']
