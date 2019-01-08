package datacrypto

import (
	"reflect"
	"testing"
)

const testKey = "test"

const value1 = "value 1"
const value2 = "value 2"
const value3 = "value 3"

const encryptedValue1 = "\x22\x1c\xec\x47\xee\x67\x53\xb0\x6f\x2a\xe5\xad\x3b\x29\x7e\xeb"
const encryptedValue3 = "\xfa\x16\x00\x67\xb4\x3c\x7a\xae\xb7\xec\xe2\x56\x10\x3a\xd5\xdf"
const encryptedSuperValue1 = "\x37\x9b\x7e\x15\x57\x1f\xee\x8f\xae\x6f\xdd\xc1\x67\x53\xa0\xdd"

type TestStruct struct {
	Field1 string `crypt:"true"`
	Field2 string
	Field3 string `crypt:"true"`
}

type testStructPointer struct {
	Field1 string `crypt:"true"`
	Field2 *string
	Field3 *string `crypt:"true"`
}

type testRecursiveStruct struct {
	Field1 string `crypt:"true"`
	Field2 string
	Field3 TestStruct
}

type testRecursiveStructPointer struct {
	Field1 string `crypt:"true"`
	Field2 *testRecursiveStruct
}

type testEmbeddedStruct struct {
	TestStruct
}

type testEmbeddedStructPointer struct {
	*TestStruct
}

func Test_aesECBSecureData_EncryptStruct(t *testing.T) {
	var value1 = value1
	var value2 = value2
	var value3 = value3

	var encryptedValue1 = encryptedValue1
	var encryptedValue3 = encryptedValue3
	var encryptedSuperValue1 = encryptedSuperValue1

	sd := NewAES128ECB(testKey)

	tests := []struct {
		name     string
		instance interface{}
		want     interface{}
		wantErr  bool
	}{
		{
			name: "Error out when a non pointer is provided",
			instance: TestStruct{
				Field1: value1,
			},
			wantErr: true,
		},
		{
			name:     "Error out when a pointer to anithing but a struct is provided",
			instance: &value2,
			wantErr:  true,
		},
		{
			name: "Encrypts only annotated fields",
			instance: &TestStruct{
				Field1: value1,
				Field2: value2,
				Field3: value3,
			},
			want: &TestStruct{
				Field1: encryptedValue1,
				Field2: value2,
				Field3: encryptedValue3,
			},
		},
		{
			name: "Encrypts annotated pointer fields",
			instance: &testStructPointer{
				Field1: value1,
				Field2: &value2,
				Field3: &value3,
			},
			want: &testStructPointer{
				Field1: encryptedValue1,
				Field2: &value2,
				Field3: &encryptedValue3,
			},
		},
		{
			name: "Encrypts structs recursivelly",
			instance: &testRecursiveStruct{
				Field1: "super value 1",
				Field2: "super value 2",
				Field3: TestStruct{
					Field1: value1,
					Field2: value2,
					Field3: value3,
				},
			},
			want: &testRecursiveStruct{
				Field1: encryptedSuperValue1,
				Field2: "super value 2",
				Field3: TestStruct{
					Field1: encryptedValue1,
					Field2: value2,
					Field3: encryptedValue3,
				},
			},
		},
		{
			name: "Encrypts structs recursivelly with pointers to struct",
			instance: &testRecursiveStructPointer{
				Field1: "super value 1",
				Field2: &testRecursiveStruct{
					Field1: "super value 1",
					Field2: "super value 2",
					Field3: TestStruct{
						Field1: value1,
						Field2: value2,
						Field3: value3,
					},
				},
			},
			want: &testRecursiveStructPointer{
				Field1: encryptedSuperValue1,
				Field2: &testRecursiveStruct{
					Field1: encryptedSuperValue1,
					Field2: "super value 2",
					Field3: TestStruct{
						Field1: encryptedValue1,
						Field2: value2,
						Field3: encryptedValue3,
					},
				},
			},
		},
		{
			name: "Encrypts embedded structs recursivelly",
			instance: &testEmbeddedStruct{
				TestStruct: TestStruct{
					Field1: value1,
					Field2: value2,
					Field3: value3,
				},
			},
			want: &testEmbeddedStruct{
				TestStruct: TestStruct{
					Field1: encryptedValue1,
					Field2: value2,
					Field3: encryptedValue3,
				},
			},
		},
		{
			name: "Encrypts embedded struct pointers recursivelly",
			instance: &testEmbeddedStructPointer{
				TestStruct: &TestStruct{
					Field1: value1,
					Field2: value2,
					Field3: value3,
				},
			},
			want: &testEmbeddedStructPointer{
				TestStruct: &TestStruct{
					Field1: encryptedValue1,
					Field2: value2,
					Field3: encryptedValue3,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sd.EncryptStruct(tt.instance)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				if !reflect.DeepEqual(got, tt.want) {
					t.Fatalf("\ngot:\n%v\n\nwant\n%v", got, tt.want)
				}
			}
		})
	}
}

func Test_aesECBSecureData_DecryptStruct(t *testing.T) {
	var value1 = value1
	var value2 = value2
	var value3 = value3

	var encryptedValue1 = encryptedValue1
	var encryptedValue3 = encryptedValue3
	var encryptedSuperValue1 = encryptedSuperValue1

	sd := NewAES128ECB(testKey)

	var someString = "some text"

	testHugo := TestStruct{
		Field1: value1,
		Field2: value2,
		Field3: value3,
	}

	tests := []struct {
		name     string
		instance interface{}
		want     interface{}
		wantErr  bool
	}{
		{
			name: "Error out when a non pointer is provided",
			instance: TestStruct{
				Field1: encryptedValue1,
			},
			wantErr: true,
		},
		{
			name:     "Error out when a pointer to anithing but a struct is provided",
			instance: &someString,
			wantErr:  true,
		},
		{
			name: "Decrypts only annotated fields",
			instance: &TestStruct{
				Field1: encryptedValue1,
				Field2: value2,
				Field3: encryptedValue3,
			},
			want: &testHugo,
		},
		{
			name: "Decrypts annotated pointer fields",
			instance: &testStructPointer{
				Field1: encryptedValue1,
				Field2: &value2,
				Field3: &encryptedValue3,
			},
			want: &testStructPointer{
				Field1: value1,
				Field2: &value2,
				Field3: &value3,
			},
		},
		{
			name: "Decrypts structs recursivelly",
			instance: &testRecursiveStruct{
				Field1: encryptedSuperValue1,
				Field2: "super value 2",
				Field3: TestStruct{
					Field1: encryptedValue1,
					Field2: value2,
					Field3: encryptedValue3,
				},
			},
			want: &testRecursiveStruct{
				Field1: "super value 1",
				Field2: "super value 2",
				Field3: TestStruct{
					Field1: value1,
					Field2: value2,
					Field3: value3,
				},
			},
		},
		{
			name: "Decrypts structs recursivelly with pointers to struct",
			instance: &testRecursiveStructPointer{
				Field1: encryptedSuperValue1,
				Field2: &testRecursiveStruct{
					Field1: encryptedSuperValue1,
					Field2: "super value 2",
					Field3: TestStruct{
						Field1: encryptedValue1,
						Field2: value2,
						Field3: encryptedValue3,
					},
				},
			},
			want: &testRecursiveStructPointer{
				Field1: "super value 1",
				Field2: &testRecursiveStruct{
					Field1: "super value 1",
					Field2: "super value 2",
					Field3: TestStruct{
						Field1: value1,
						Field2: value2,
						Field3: value3,
					},
				},
			},
		},
		{
			name: "Decrypts embedded structs recursivelly",
			instance: &testEmbeddedStruct{
				TestStruct: TestStruct{
					Field1: encryptedValue1,
					Field2: value2,
					Field3: encryptedValue3,
				},
			},
			want: &testEmbeddedStruct{
				TestStruct: TestStruct{
					Field1: value1,
					Field2: value2,
					Field3: value3,
				},
			},
		},
		{
			name: "Decrypts embedded struct pointers recursivelly",
			instance: &testEmbeddedStructPointer{
				TestStruct: &TestStruct{
					Field1: encryptedValue1,
					Field2: value2,
					Field3: encryptedValue3,
				},
			},
			want: &testEmbeddedStructPointer{
				TestStruct: &TestStruct{
					Field1: value1,
					Field2: value2,
					Field3: value3,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sd.DecryptStruct(tt.instance)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				if !reflect.DeepEqual(got, tt.want) {
					t.Fatalf("\ngot:\n%v\n\nwant\n%v", got, tt.want)
				}
			}
		})
	}
}
