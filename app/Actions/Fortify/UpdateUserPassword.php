<?php

namespace App\Actions\Fortify;

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Laravel\Fortify\Contracts\UpdatesUserPasswords;
use Illuminate\Validation\Rules\Password;


class UpdateUserPassword implements UpdatesUserPasswords
{
    use PasswordValidationRules;

    /**
     * Validate and update the user's password.
     *
     * @param  array<string, string>  $input
     */
    public function update(User $user, array $input): void
    {
        Validator::make($input, [
            'current_password' => ['required', 'string', 'current_password:web'],
        'password' => ['required', 'string', 'confirmed',
            Password::min(8)       // Minimal 8 karakter
                    ->letters()    // Wajib ada setidaknya satu huruf
                    ->mixedCase()  // Wajib ada huruf besar dan kecil
                    ->numbers()    // Wajib ada setidaknya satu angka
                    ->symbols()    // Wajib ada setidaknya satu simbol
        ],
            ], [
            'current_password.current_password' => __('The provided password does not match your current password.'),
        ])->validateWithBag('updatePassword');

        $user->forceFill([
            'password' => Hash::make($input['password']),
        ])->save();
    }
}
