; Test case sensitivity
; { dg-do assemble }
; { dg-options "--mcpu=arc700" }
  mov   %blink, %Blink
        ; { dg-error "Error: bad expression" "" { target *-*-* } 4 }
        ; { dg-error "Error: junk at end of line: `Blink'" "" { target *-*-* } 4 }
  mov   %blink, %BLINK
        ; { dg-error "Error: bad expression" "" { target *-*-* } 7 }
        ; { dg-error "Error: junk at end of line: `BLINK'" "" { target *-*-* } 7 }
