# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: potato.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='potato.proto',
  package='',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=_b('\n\x0cpotato.proto\" \n\x0cGreetRequest\x12\x10\n\x08hostname\x18\x01 \x01(\t\"\x1e\n\rGreetResponse\x12\r\n\x05greet\x18\x01 \x01(\t\"7\n\x18PerformanceFeatureVector\x12\x0c\n\x04name\x18\x01 \x03(\t\x12\r\n\x05value\x18\x02 \x03(\x02\"G\n\x0bHintRequest\x12\x10\n\x08hostname\x18\x01 \x01(\t\x12&\n\x03pfv\x18\x02 \x01(\x0b\x32\x19.PerformanceFeatureVector\"2\n\x0cHintResponse\x12\x0c\n\x04hint\x18\x01 \x01(\t\x12\x14\n\x0c\x64ocker_image\x18\x02 \x01(\t21\n\x05Greet\x12(\n\x05Greet\x12\r.GreetRequest\x1a\x0e.GreetResponse\"\x00\x32-\n\x04Hint\x12%\n\x04Hint\x12\x0c.HintRequest\x1a\r.HintResponse\"\x00\x62\x06proto3')
)




_GREETREQUEST = _descriptor.Descriptor(
  name='GreetRequest',
  full_name='GreetRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='hostname', full_name='GreetRequest.hostname', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=16,
  serialized_end=48,
)


_GREETRESPONSE = _descriptor.Descriptor(
  name='GreetResponse',
  full_name='GreetResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='greet', full_name='GreetResponse.greet', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=50,
  serialized_end=80,
)


_PERFORMANCEFEATUREVECTOR = _descriptor.Descriptor(
  name='PerformanceFeatureVector',
  full_name='PerformanceFeatureVector',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='name', full_name='PerformanceFeatureVector.name', index=0,
      number=1, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='value', full_name='PerformanceFeatureVector.value', index=1,
      number=2, type=2, cpp_type=6, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=82,
  serialized_end=137,
)


_HINTREQUEST = _descriptor.Descriptor(
  name='HintRequest',
  full_name='HintRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='hostname', full_name='HintRequest.hostname', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='pfv', full_name='HintRequest.pfv', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=139,
  serialized_end=210,
)


_HINTRESPONSE = _descriptor.Descriptor(
  name='HintResponse',
  full_name='HintResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='hint', full_name='HintResponse.hint', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='docker_image', full_name='HintResponse.docker_image', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=212,
  serialized_end=262,
)

_HINTREQUEST.fields_by_name['pfv'].message_type = _PERFORMANCEFEATUREVECTOR
DESCRIPTOR.message_types_by_name['GreetRequest'] = _GREETREQUEST
DESCRIPTOR.message_types_by_name['GreetResponse'] = _GREETRESPONSE
DESCRIPTOR.message_types_by_name['PerformanceFeatureVector'] = _PERFORMANCEFEATUREVECTOR
DESCRIPTOR.message_types_by_name['HintRequest'] = _HINTREQUEST
DESCRIPTOR.message_types_by_name['HintResponse'] = _HINTRESPONSE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

GreetRequest = _reflection.GeneratedProtocolMessageType('GreetRequest', (_message.Message,), dict(
  DESCRIPTOR = _GREETREQUEST,
  __module__ = 'potato_pb2'
  # @@protoc_insertion_point(class_scope:GreetRequest)
  ))
_sym_db.RegisterMessage(GreetRequest)

GreetResponse = _reflection.GeneratedProtocolMessageType('GreetResponse', (_message.Message,), dict(
  DESCRIPTOR = _GREETRESPONSE,
  __module__ = 'potato_pb2'
  # @@protoc_insertion_point(class_scope:GreetResponse)
  ))
_sym_db.RegisterMessage(GreetResponse)

PerformanceFeatureVector = _reflection.GeneratedProtocolMessageType('PerformanceFeatureVector', (_message.Message,), dict(
  DESCRIPTOR = _PERFORMANCEFEATUREVECTOR,
  __module__ = 'potato_pb2'
  # @@protoc_insertion_point(class_scope:PerformanceFeatureVector)
  ))
_sym_db.RegisterMessage(PerformanceFeatureVector)

HintRequest = _reflection.GeneratedProtocolMessageType('HintRequest', (_message.Message,), dict(
  DESCRIPTOR = _HINTREQUEST,
  __module__ = 'potato_pb2'
  # @@protoc_insertion_point(class_scope:HintRequest)
  ))
_sym_db.RegisterMessage(HintRequest)

HintResponse = _reflection.GeneratedProtocolMessageType('HintResponse', (_message.Message,), dict(
  DESCRIPTOR = _HINTRESPONSE,
  __module__ = 'potato_pb2'
  # @@protoc_insertion_point(class_scope:HintResponse)
  ))
_sym_db.RegisterMessage(HintResponse)



_GREET = _descriptor.ServiceDescriptor(
  name='Greet',
  full_name='Greet',
  file=DESCRIPTOR,
  index=0,
  serialized_options=None,
  serialized_start=264,
  serialized_end=313,
  methods=[
  _descriptor.MethodDescriptor(
    name='Greet',
    full_name='Greet.Greet',
    index=0,
    containing_service=None,
    input_type=_GREETREQUEST,
    output_type=_GREETRESPONSE,
    serialized_options=None,
  ),
])
_sym_db.RegisterServiceDescriptor(_GREET)

DESCRIPTOR.services_by_name['Greet'] = _GREET


_HINT = _descriptor.ServiceDescriptor(
  name='Hint',
  full_name='Hint',
  file=DESCRIPTOR,
  index=1,
  serialized_options=None,
  serialized_start=315,
  serialized_end=360,
  methods=[
  _descriptor.MethodDescriptor(
    name='Hint',
    full_name='Hint.Hint',
    index=0,
    containing_service=None,
    input_type=_HINTREQUEST,
    output_type=_HINTRESPONSE,
    serialized_options=None,
  ),
])
_sym_db.RegisterServiceDescriptor(_HINT)

DESCRIPTOR.services_by_name['Hint'] = _HINT

# @@protoc_insertion_point(module_scope)
