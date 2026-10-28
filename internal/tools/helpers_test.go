package tools

import "k8s.io/apimachinery/pkg/util/intstr"

func intstrFromInt(i int) intstr.IntOrString { return intstr.FromInt32(int32(i)) }
