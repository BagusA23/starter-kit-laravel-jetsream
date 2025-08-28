<?php

namespace App\Actions\Fortify;

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Laravel\Fortify\Contracts\ResetsUserPasswords;
use Illuminate\Validation\Rules\Password;


class ResetUserPassword implements ResetsUserPasswords
{
    use PasswordValidationRules;

    /**
     * Validate and reset the user's forgotten password.
     *
     * @param  array<string, string>  $input
     */
    public function reset(User $user, array $input): void
    {
        Validator::make($input, [
        'password' => ['required', 'string', 'confirmed',
            Password::min(8)       // Minimal 8 karakter
                    ->letters()    // Wajib ada setidaknya satu huruf
                    ->mixedCase()  // Wajib ada huruf besar dan kecil
                    ->numbers()    // Wajib ada setidaknya satu angka
                    ->symbols()    // Wajib ada setidaknya satu simbol
        ],
        ])->validate();

        $user->forceFill([
            'password' => Hash::make($input['password']),
        ])->save();
    }
}
