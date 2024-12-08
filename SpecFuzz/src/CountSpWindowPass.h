#ifndef LLVM_TRANSFORMS_SCALAR_SROA_H
#define LLVM_TRANSFORMS_SCALAR_SROA_H

#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Value.h"
#include "llvm/Pass.h"
#include "llvm/PassRegistry.h"

namespace llvm {

void initializeCountSpWindowPassPass (PassRegistry &);

class CountSpWindowPass : public FunctionPass {
public:
    static char ID;
    CountSpWindowPass (): FunctionPass(ID) {
        initializeCountSpWindowPassPass (*PassRegistry::getPassRegistry());
    } 
    auto runOnFunction(Function &F) -> bool override;

private:
    int NumInstructionsUntilNextCheck = 0;
    int MinCheckInterval = 15;
    auto visitFunction(Function &F) -> bool;
    auto visitFunctionEntry(Instruction &I, BasicBlock &BB) -> bool;
    auto visitBBEntry(Instruction &I, BasicBlock &BB) -> bool;
    auto countRealInstructions(BasicBlock &BB) -> int;
};

} // namespace llvm

#endif 
