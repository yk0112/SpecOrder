#include "llvm/Transforms/Scalar/CountSpWindowPass.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Value.h"
#include "llvm/Pass.h"
#include "llvm/IR/IntrinsicInst.h" 
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/Transforms/Scalar.h"

using namespace llvm;
#define DEBUG_TYPE "SpecEm" 
#define PASS_DESCRIPTION "Count speculative window for simulate Spectre v1"

char CountSpWindowPass::ID = 0;


auto CountSpWindowPass::runOnFunction(Function &F) -> bool {
    return visitFunction(F);
}

auto CountSpWindowPass::visitFunction(Function &F) -> bool {
    bool Modified = false;
    
    if (F.isDeclaration())
        return Modified;
    
    if (F.getName().contains("asan")) {
        DEBUG(dbgs() << "Blacklisted\n");
        return Modified;
    }
    
    std::vector<BasicBlock *> OriginalBBs;
    for (BasicBlock &BB : F)
        OriginalBBs.push_back(&BB);

    for (BasicBlock *BB : OriginalBBs) {
        std::vector<Instruction *> OriginalInsts;
        for (Instruction &I : *BB)
            OriginalInsts.push_back(&I);
        
        bool FirstInstInBB = true;
        NumInstructionsUntilNextCheck = countRealInstructions(*BB);

        for (Instruction *I : OriginalInsts) {
            if (isa<DbgInfoIntrinsic>(I))
                continue;
            
            NumInstructionsUntilNextCheck--;

            if (FirstInstInBB && !isa<PHINode>(I)) {
                Modified |= visitBBEntry(*I, *BB);
                FirstInstInBB = false;
            }
            // if (NumInstructionsUntilNextCheck <= 0) {
            //     Modified |= insertAdditionalCheck(*I, *BB, NumInstructionsUntilNextCheck);
            //     NumInstructionsUntilNextCheck =
            //         MinCheckInterval + NumInstructionsUntilNextCheck + 1;
            // }
        }
    }
    return Modified;
}

auto CountSpWindowPass::visitBBEntry(Instruction &I, BasicBlock &BB) -> bool {
     LLVMContext &Context = BB.getContext();
     IRBuilder<> Builder(&I);
     
     Module *M = BB.getModule();
     LLVMContext &Ctx = M->getContext();
     GlobalVariable *InstrCounter = M->getGlobalVariable("instruction_counter");

     if (!InstrCounter) {
        DEBUG(dbgs() << "Declaring external instruction_counter variable.\n");
        InstrCounter = new GlobalVariable(
            *M,                           
            Type::getInt64Ty(Ctx),             
            false,                             
            GlobalValue::ExternalLinkage,      
            nullptr,                           
            "instruction_counter"              
        );  
     }   
     
    if (NumInstructionsUntilNextCheck == 0) {
        return false;
    }

    Value *CurrentValue = Builder.CreateLoad(
        Type::getInt64Ty(Context),
        InstrCounter,
        "current_counter"
    );
    
    Value *DecrementValue = ConstantInt::get(Type::getInt64Ty(Context), NumInstructionsUntilNextCheck);

    Value *UpdatedValue = Builder.CreateSub(CurrentValue, DecrementValue, "updated_counter");

    Builder.CreateStore(UpdatedValue, InstrCounter);

    return true;
}

auto CountSpWindowPass::countRealInstructions(BasicBlock &BB) -> int {
    int count = 0;

    for (Instruction &I : BB) {
        if (isa<DbgInfoIntrinsic>(&I)) {
            continue;
        }
        count++;
    }

    if (count == 0)
        return 0;

    if ((count % MinCheckInterval) == 0)
        return MinCheckInterval + 1;

    return (count % MinCheckInterval) + 1;
}


FunctionPass *llvm::createCountSpWindowPass() {
  return new CountSpWindowPass();
}

INITIALIZE_PASS_BEGIN(CountSpWindowPass, DEBUG_TYPE, PASS_DESCRIPTION, false, false)
INITIALIZE_PASS_END(CountSpWindowPass, DEBUG_TYPE, PASS_DESCRIPTION, false, false)


