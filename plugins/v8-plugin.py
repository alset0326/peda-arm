import struct
import config
import traceback
from utils import *
from v8_globals import *


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


def to_dword(s, num=1):
    result = struct.unpack('<' + 'I' * num, s)
    return result[0] if num == 1 else result


def to_byte(data, num=1):
    result = struct.unpack('<' + 'B' * num, data)
    return result[0] if num == 1 else result


def read(data, offset, size=kPointerSize):
    end = min(offset + size, len(data))
    return data[offset:end]


def get_dword_smi(data, offset):
    return smi_to_int(to_dword(read(data, offset)))


def get_dword(data, offset):
    return to_dword(read(data, offset))


def get_byte(data, offset):
    return to_byte(read(data, offset, 1))


######################################################################################
#                                   JS classes                                       #
######################################################################################

class Object:
    """
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
        if self.size != size:
            self.data = self.handle.data(size)
            self.size = size

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
    HeapObject is the superclass for all classes describing heap allocated
    objects.
    """
    kMapOffset = Object.kHeaderSize
    kHeaderSize = kMapOffset + kPointerSize

    kSize = kHeaderSize  # for mem dump needed

    @staticmethod
    def get_map_addr(data):
        return get_dword(data, HeapObject.kMapOffset)

    def do_parse(self):
        Object.do_parse(self)
        self.append('kMapAddr: 0x%x' % HeapObject.get_map_addr(self.data))


class Map(HeapObject):
    """
    All heap objects have a Map that describes their structure.
     A Map contains information about:
     - Size information about the object
     - How to iterate over an object (for garbage collection)
    """
    kInstanceSizesOffset = HeapObject.kHeaderSize
    kInstanceAttributesOffset = kInstanceSizesOffset + kIntSize
    kBitField3Offset = kInstanceAttributesOffset + kIntSize
    kPrototypeOffset = kBitField3Offset + kPointerSize
    kConstructorOffset = kPrototypeOffset + kPointerSize
    kTransitionsOrBackPointerOffset = kConstructorOffset + kPointerSize
    kDescriptorsOffset = kTransitionsOrBackPointerOffset + kPointerSize
    kCodeCacheOffset = kDescriptorsOffset + kPointerSize
    kDependentCodeOffset = kCodeCacheOffset + kPointerSize
    kSize = kDependentCodeOffset + kPointerSize

    @staticmethod
    def get_type(data):
        return get_byte(data, Map.kInstanceAttributesOffset)

    @staticmethod
    def get_class(data):
        return Map.type_to_class(Map.get_type(data))

    @staticmethod
    def type_to_class(type_num):
        if type_num in TYPE_TO_CLASS:
            return TYPE_TO_CLASS.get(type_num)
        warning('InstanceType %d not supported.' % type_num)
        return None

    @staticmethod
    def get_instance_size(data):
        return get_byte(data, Map.kInstanceSizesOffset) << kPointerSizeLog2

    @staticmethod
    def get_instance_attributes(data):
        return get_dword(data, Map.kInstanceAttributesOffset)

    @staticmethod
    def get_bid_field3(data):
        return get_dword(data, Map.kBitField3Offset)

    @staticmethod
    def get_prototype(data):
        return get_dword(data, Map.kPrototypeOffset)

    @staticmethod
    def get_constructor(data):
        return get_dword(data, Map.kConstructorOffset)

    @staticmethod
    def get_transitions_or_back_pointer(data):
        return get_dword(data, Map.kTransitionsOrBackPointerOffset)

    @staticmethod
    def get_descriptors(data):
        return get_dword(data, Map.kDescriptorsOffset)

    @staticmethod
    def get_code_cache(data):
        return get_dword(data, Map.kCodeCacheOffset)

    @staticmethod
    def get_dependent_code(data):
        return get_dword(data, Map.kDependentCodeOffset)

    def do_parse(self):
        HeapObject.do_parse(self)
        self.append('InstanceSizes: 0x%x' % self.get_instance_size(self.data))
        self.append('InstanceAttributes: 0x%x' % self.get_instance_attributes(self.data))
        self.append('BitField3: 0x%x' % self.get_bid_field3(self.data))
        self.append('Prototype: 0x%x' % self.get_prototype(self.data))
        self.append('Constructor: 0x%x' % self.get_constructor(self.data))
        self.append('TransitionsOrBackPointer: 0x%x' % self.get_transitions_or_back_pointer(self.data))
        self.append('Descriptors: 0x%x' % self.get_descriptors(self.data))
        self.append('CodeCache: 0x%x' % self.get_code_cache(self.data))
        self.append('DependentCode: 0x%x' % self.get_dependent_code(self.data))


class JSReceiver(HeapObject):
    """
    JSReceiver includes types on which properties can be defined, i.e.,
    JSObject and JSProxy.
    """


class JSObject(JSReceiver):
    """
    The JSObject describes real heap allocated JavaScript objects with
    properties.
    Note that the map of JSObject changes during execution to enable inline
    caching.
    """
    kPropertiesOffset = HeapObject.kHeaderSize
    kElementsOffset = kPropertiesOffset + kPointerSize
    kHeaderSize = kElementsOffset + kPointerSize

    kSize = kHeaderSize  # for mem dump needed

    @staticmethod
    def get_properties(data):
        return get_dword(data, JSObject.kPropertiesOffset)

    @staticmethod
    def get_elements_addr(data):
        return get_dword(data, JSObject.kElementsOffset)

    def do_parse(self):
        JSReceiver.do_parse(self)
        self.append('kProperties: 0x%x' % JSObject.get_properties(self.data))
        self.append('kElementsAddr: 0x%x' % JSObject.get_elements_addr(self.data))


class JSArray(JSObject):
    """
    The JSArray describes JavaScript Arrays
     Such an array can be in one of two modes:
       - fast, backing storage is a FixedArray and length <= elements.length()
          Please note: push and pop can be used to grow and shrink the array.
       - slow, backing storage is a HashTable with numbers as keys.
    """
    kLengthOffset = JSObject.kHeaderSize
    kSize = kLengthOffset + kPointerSize

    @staticmethod
    def get_length(data):
        return get_dword_smi(data, JSArray.kLengthOffset)

    def do_parse(self):
        JSObject.do_parse(self)
        self.append('kLength: 0x%x' % JSArray.get_length(self.data))


class JSArrayBuffer(JSObject):
    """
    The JSArrayBuffer
    """
    kBackingStoreOffset = JSObject.kHeaderSize
    kByteLengthOffset = kBackingStoreOffset + kPointerSize
    kFlagOffset = kByteLengthOffset + kPointerSize
    kWeakNextOffset = kFlagOffset + kPointerSize
    kWeakFirstViewOffset = kWeakNextOffset + kPointerSize
    kSize = kWeakFirstViewOffset + kPointerSize

    @staticmethod
    def get_backing_store_addr(data):
        return get_dword(data, JSArrayBuffer.kBackingStoreOffset)

    @staticmethod
    def get_byte_length(data):
        return get_dword_smi(data, JSArrayBuffer.kByteLengthOffset)

    @staticmethod
    def get_flag(data):
        return get_dword(data, JSArrayBuffer.kFlagOffset)

    @staticmethod
    def get_weak_next_addr(data):
        return get_dword(data, JSArrayBuffer.kWeakNextOffset)

    @staticmethod
    def get_weak_first_view_addr(data):
        return get_dword(data, JSArrayBuffer.kBackingStoreOffset)

    def do_parse(self):
        JSObject.do_parse(self)
        self.append('kBackingStoreAddr: 0x%x' % JSArrayBuffer.get_backing_store_addr(self.data))
        self.append('kByteLength: 0x%x' % JSArrayBuffer.get_byte_length(self.data))
        self.append('kFlag: 0x%x' % JSArrayBuffer.get_flag(self.data))
        self.append('kWeakNextAddr: 0x%x' % JSArrayBuffer.get_weak_next_addr(self.data))
        self.append('kWeakFirstView: 0x%x' % JSArrayBuffer.get_weak_first_view_addr(self.data))


class FixedArrayBase(HeapObject):
    """
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
    FixedArray describes fixed-sized arrays with element type Object*.
    """

    def get_elements(self):
        length = FixedArray.get_length(self.data)
        self.update_size(self.kSize + 4 * length)
        elements = to_dword(read(self.data, self.kSize, 4 * length), length)
        elements = [str(smi_to_int(i)) if has_smi_tag(i) else '0x%x' % i for i in elements]
        return elements

    def do_parse(self):
        FixedArrayBase.do_parse(self)
        self.append('Elements: [%s]' % ',\t'.join(self.get_elements()))


class Name(HeapObject):
    """
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


class String(Name):
    """
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
    The SeqString abstract class captures sequential string values.
    """

    # Layout description.
    kHeaderSize = String.kSize

    kSize = kHeaderSize  # for mem dump needed

    def get_string(self):
        length = self.get_length(self.data)
        self.update_size(self.kSize + length)
        return read(self.data, self.kSize, length)

    def do_parse(self):
        SeqString.do_parse(self)
        self.append('String: %s' % self.get_string())


class SeqOneByteString(SeqString):
    """
    The OneByteString class captures sequential one-byte string objects.
    Each character in the OneByteString is an one-byte character.
    """


class SeqTwoByteString(SeqString):
    """
    The TwoByteString class captures sequential unicode string objects.
    Each character in the TwoByteString is a two-byte uint16_t.
    """


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

        Returns: data (str)

        """
        # Double Check
        location = raw_heap_object(self._location) if has_heap_object_tag(self._location) else self._location
        data = peda.readmem(location, size)
        if data is None:
            warn_log = "Cannot access memory at address 0x%x" % location
            warning(warn_log)
            raise MemoryError(warn_log)
        return data

    def get_instance_type(self):
        """
        Get Handle's instanceType
        Returns: type num (int)

        """
        map_handle = Handle(HeapObject.get_map_addr(self.data(kPointerSize)))
        return Map.get_type(map_handle.data(Map.kSize))

    def parse(self, bitness=32):
        """
        Auto parse the Handle
        Args:
            bitness: arch bitness (int)

        Returns: parse result (list)

        """
        if self._type is not None and self._class is not None and Map.type_to_class(self._type) != self._class:
            self._type = self._class = None
        if self._type is None:
            if has_smi_tag(self._location):
                return smi_to_int(self._location)
            elif has_failure_tag(self._location):
                return ['Has failure tag. Maybe Failure Object?']
            elif has_heap_object_tag(self._location):
                self._type = self.get_instance_type()
            else:
                return None
        if self._class is None:
            self._class = Map.type_to_class(self._type)
        if self._class is not None:
            c = self._class(self)
            try:
                result = c.parse()
                result.insert(0, 'DESCRIPTION:%s' % self._class.__doc__)
                result.insert(0, 'Heap Pointer: 0x%x' % raw_heap_object(self._location))
                return result
            except Exception as e:
                if config.Option.get("debug") == "on":
                    msg("Exception: %s" % e)
                    traceback.print_exc()
                warning('Parse 0x%x failed' % self._location)
        return None


######################################################################################
#                                      main                                          #
######################################################################################

peda = None

NAME_TO_TYPE = {
    'array': InstanceType.JS_ARRAY_TYPE,
    'object': InstanceType.JS_OBJECT_TYPE,
    'arraybuffer': InstanceType.JS_ARRAY_BUFFER_TYPE
}

TYPE_TO_CLASS = {
    InstanceType.JS_ARRAY_TYPE: JSArray,
    InstanceType.FIXED_ARRAY_TYPE: FixedArray,
    InstanceType.JS_OBJECT_TYPE: JSObject,
    InstanceType.JS_ARRAY_BUFFER_TYPE: JSArrayBuffer,
    InstanceType.ONE_BYTE_STRING_TYPE: SeqOneByteString,
    InstanceType.MAP_TYPE: Map
}


def invoke(peda_, *arg):
    """
    V8 debug helper
    Usage:
        v8 [addr]
    """
    global peda
    peda = peda_
    (opt, addr) = normalize_argv(arg, 2)
    if opt is None:
        try:
            v = peda.parse_and_eval('$')
        except:
            warning('gdb history is empty')
            return
    else:
        v = opt
    a = to_int(v)
    if a is None:
        warning('Invalid arguments')
        return
    h = Handle(a)
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

# invoke.options = ['handle', 'addr', 'map']
