<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StoreCommentRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return false;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            // 'post_id' harus ada dan harus merupakan ID yang valid di tabel 'posts'
            'post_id' => 'required|exists:posts,id',

            // 'body' harus ada, berupa teks, minimal 10 karakter, maksimal 2000
            'body' => 'required|string|min:10|max:2000',
        ];
    }
}
