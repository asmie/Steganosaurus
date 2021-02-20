using MvvmCross.IoC;
using MvvmCross.ViewModels;
using Steganosaurus.Core.ViewModels.Root;

namespace Steganosaurus.Core
{
    public class App : MvxApplication
    {
        public override void Initialize()
        {
            CreatableTypes()
                .EndingWith("Service")
                .AsInterfaces()
                .RegisterAsLazySingleton();

            RegisterAppStart<RootViewModel>();
        }
    }
}
