; ModuleID = 'probe4.c1fbc3dd-cgu.0'
source_filename = "probe4.c1fbc3dd-cgu.0"
target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-apple-macosx10.7.0"

@alloc_fa3774094ca4fce6c25f2692847466ee = private unnamed_addr constant <{ [83 x i8] }> <{ [83 x i8] c"/private/tmp/rust-20230614-7623-1mhz7p/rustc-1.70.0-src/library/core/src/num/mod.rs" }>, align 1
@alloc_875ccb2c9d1a94c51bd71db0b39ec048 = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_fa3774094ca4fce6c25f2692847466ee, [16 x i8] c"S\00\00\00\00\00\00\00/\04\00\00\05\00\00\00" }>, align 8
@str.0 = internal constant [25 x i8] c"attempt to divide by zero"

; probe4::probe
; Function Attrs: uwtable
define void @_ZN6probe45probe17hb67ac3dee9515c02E() unnamed_addr #0 {
start:
  %0 = call i1 @llvm.expect.i1(i1 false, i1 false)
  br i1 %0, label %panic.i, label %"_ZN4core3num21_$LT$impl$u20$u32$GT$10div_euclid17h63f128be56a1198eE.exit"

panic.i:                                          ; preds = %start
; call core::panicking::panic
  call void @_ZN4core9panicking5panic17h679db5d92a389689E(ptr align 1 @str.0, i64 25, ptr align 8 @alloc_875ccb2c9d1a94c51bd71db0b39ec048) #3
  unreachable

"_ZN4core3num21_$LT$impl$u20$u32$GT$10div_euclid17h63f128be56a1198eE.exit": ; preds = %start
  ret void
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(none)
declare i1 @llvm.expect.i1(i1, i1) #1

; core::panicking::panic
; Function Attrs: cold noinline noreturn uwtable
declare void @_ZN4core9panicking5panic17h679db5d92a389689E(ptr align 1, i64, ptr align 8) unnamed_addr #2

attributes #0 = { uwtable "frame-pointer"="all" "probe-stack"="inline-asm" "target-cpu"="core2" }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(none) }
attributes #2 = { cold noinline noreturn uwtable "frame-pointer"="all" "probe-stack"="inline-asm" "target-cpu"="core2" }
attributes #3 = { noreturn }

!llvm.module.flags = !{!0}

!0 = !{i32 8, !"PIC Level", i32 2}
